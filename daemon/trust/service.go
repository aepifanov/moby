package trust // import "github.com/docker/docker/daemon/trust"

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/log"
	"github.com/distribution/reference"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	registryapi "github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/theupdateframework/notary/storage"
	"github.com/theupdateframework/notary/tuf/data"
)

// Service provides a backend for trust validation
type Service struct {
	TrustCachePath  string
	RegistryService RegistryService
}

// RegistryService provides registry information needed for trust validation.
type RegistryService interface {
	ResolveRepository(ref reference.Named) (*registry.RepositoryInfo, error)
	TLSConfig(registryName string) (*tls.Config, error)
}

func (s *Service) log(ctx context.Context) *log.Entry {
	return log.G(ctx).WithField("content-trust", nil)
}

func combineRootKeys(cfg *config.ContentTrust) map[string][]string {
	if cfg == nil { // content-trust is not set
		return nil
	}
	rootKeys := make(map[string][]string)
	if cfg.TrustPinning.OfficialLibraryImages {
		rootKeys["docker.io/library/*"] = officialImagesRootKeys
	}
	// the provided root keys take precedence over the official pinned root keys
	for key, val := range cfg.TrustPinning.RootKeys {
		rootKeys[key] = val
	}
	return rootKeys
}

func (s *Service) warnIfPermissive(ctx context.Context, mode config.TrustMode, err error) error {
	if err == nil {
		return nil
	}
	if mode == config.TrustModePermissive {
		s.log(ctx).Warn(err)
		return nil
	}
	return err
}

// VerifyImageSigned takes an image reference and converts it to a canonical reference, if the image is signed.
// Otherwise, returns an error.
func (s *Service) VerifyImageSigned(ctx context.Context, cfg *config.ContentTrust, ref reference.Named, authConfig *registryapi.AuthConfig, headers map[string][]string) (reference.Canonical, error) {
	if cfg == nil {
		return nil, fmt.Errorf("content-trust config is nil")
	}
	trustStore, trustStoreErr := s.getTrustStore(ctx, ref, authConfig, headers)
	log := s.log(ctx)
	logf := log.Errorf

	mode := cfg.Mode
	keyIDs := combineRootKeys(cfg)
	certIDs := cfg.TrustPinning.CertIDs
	ignoreExpiry := cfg.AllowExpiredCachedTrustData

	if trustStoreErr != nil {
		// Just try to use the cache instead
		if mode == config.TrustModePermissive {
			logf = log.Warnf
		}
		logf("Error looking up trust server for %s: %v", ref.Name(), trustStoreErr)
	}

	cache, err := s.getTrustCache(ref)
	if err != nil {
		return nil, s.warnIfPermissive(ctx, cfg.Mode, errors.Wrapf(err, "unable to access trust cache for %s", ref.Name()))
	}

	v := &verifier{
		cache:        cache,
		keyIDs:       keyIDs,
		certIDs:      certIDs,
		ignoreExpiry: ignoreExpiry,
	}
	canonicalRef, err := v.VerifyImage(ref, trustStore)
	if err != nil {
		return nil, s.warnIfPermissive(ctx, cfg.Mode, err)
	}
	return canonicalRef, err
}

// getTrustCache takes an image ref, and returns the cache that will be used to store
// trust data for that image.  NewFileStore will create all the necessary directories.
// nolint: interfacer
func (s *Service) getTrustCache(ref reference.Named) (*storage.FilesystemStore, error) {
	imagePath := filepath.Join(s.TrustCachePath, filepath.FromSlash(ref.Name()))
	return storage.NewFileStore(imagePath, "json")
}

// getTrustStore takes an auth config and an image ref, and returns a storage.RemoteStore
// that can be used to download new trust data.  Much of this comes from
// github.com/docker/cli/trust/trust.go's GetNotaryRepository code, with some info
// from distribution/registry.go
// Note that this assumes that the trust store matches the registry name - if we allow
// configuration of separate trust servers, then this function would need to be modified
func (s *Service) getTrustStore(ctx context.Context, ref reference.Named, authConfig *registryapi.AuthConfig, metaHeaders map[string][]string) (storage.RemoteStore, error) {

	repoInfo, err := s.RegistryService.ResolveRepository(ref)
	if err != nil {
		return nil, err
	}

	server := officialNotaryServer
	if !repoInfo.Index.Official {
		if repoInfo.Index.Secure {
			server = "https://" + repoInfo.Index.Name
		} else {
			server = "http://" + repoInfo.Index.Name
		}
	}
	server = strings.TrimRight(server, "/")

	tlsConfig, err := s.RegistryService.TLSConfig(repoInfo.Index.Name)
	if err != nil {
		return nil, err
	}

	// --- stolen from distribution/registry.go ---
	direct := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	base := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         direct.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   true,
	}

	modifiers := registry.Headers(dockerversion.DockerUserAgent(ctx), metaHeaders)
	authTransport := transport.NewTransport(base, modifiers...)

	challengeManager, err := pingNotary(server, authTransport)
	if err != nil {
		return nil, err
	}

	if authConfig != nil && authConfig.RegistryToken != "" {
		passThruTokenHandler := &existingTokenHandler{token: authConfig.RegistryToken}
		modifiers = append(modifiers, auth.NewAuthorizer(challengeManager, passThruTokenHandler))
	} else {
		scope := auth.RepositoryScope{
			Repository: ref.Name(),
			Actions:    []string{"pull"}, // we only need read access
			Class:      repoInfo.Class,
		}

		creds := registry.NewStaticCredentialStore(authConfig)
		tokenHandlerOptions := auth.TokenHandlerOptions{
			Transport:   authTransport,
			Credentials: creds,
			Scopes:      []auth.Scope{scope},
			ClientID:    registry.AuthClientID,
		}
		tokenHandler := auth.NewTokenHandlerWithOptions(tokenHandlerOptions)
		basicHandler := auth.NewBasicHandler(creds)
		modifiers = append(modifiers, auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler))
	}
	tr := transport.NewTransport(base, modifiers...)

	// -------- end stolen code --------

	// Note, the GUN includes the registry name
	return storage.NewNotaryServerStore(server, data.GUN(ref.Name()), tr)
}

// pingNotary is stolen from registry/auth.go - it's similar to pinging a v2
// registry, but we don't care about the version, only that we get a
// challenge manager for the supported authentication types.  We ignore actual
// ping errors, because trust can operate from cache.
func pingNotary(endpoint string, transport http.RoundTripper) (challenge.Manager, error) {
	pingClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
	endpoint = endpoint + "/v2/"
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	challengeManager := challenge.NewSimpleManager()
	resp, err := pingClient.Do(req)
	// Ignore error on ping to operate in offline mode
	if err == nil {
		defer resp.Body.Close()
		if err := challengeManager.AddResponse(resp); err != nil {
			return nil, err
		}
	}

	return challengeManager, nil
}

// Mode returns the configured content-trust mode
func Mode(cfg *config.ContentTrust) config.TrustMode {
	if cfg == nil {
		return config.TrustModeDisabled
	}
	return cfg.Mode
}

// ---- This also comes from distribution/registry.go ----

type existingTokenHandler struct {
	token string
}

func (th *existingTokenHandler) Scheme() string {
	return "bearer"
}

func (th *existingTokenHandler) AuthorizeRequest(req *http.Request, params map[string]string) error {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", th.token))
	return nil
}
