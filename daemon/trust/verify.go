package trust // import "github.com/docker/docker/daemon/trust"

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path"
	"strings"

	"github.com/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/client"
	"github.com/theupdateframework/notary/storage"
	"github.com/theupdateframework/notary/trustpinning"
	"github.com/theupdateframework/notary/tuf"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/signed"
)

// The trust package is used for the engine to do signing verification.

// officialNotaryServer is the hub server that by default is used for docker.io images
const officialNotaryServer = "https://notary.docker.io"

var (
	// releasesRole refers to the "targets/releases" role that docker prioritizes as the role that
	// contains tag data by default
	releasesRole = data.RoleName(path.Join(data.CanonicalTargetsRole.String(), "releases"))
)

// metaCache is the same as MetadataStore but also lists files so that we can copy
// cached data over
type metaCache interface {
	storage.MetadataStore
	ListFiles() []string
}

// verifier is an object which provides a `VerifyImage` function.  The assumption is
// that everything needed to verify an image will likely be the same, except possibly
// we might want to try multiple remote stores (hence remote store is accepted as a
// parameter to the one function on verifier that is exported).
type verifier struct {
	cache  metaCache
	keyIDs map[string][]string
	// TODO: add unit tests for certIDs
	certIDs      map[string][]string
	ignoreExpiry bool
}

// loadFromCache just uses an offline store, so everything is loaded from the cache -
// we can directly use the cache without worrying about corruption, because nothing will
// be written to cache
func (v *verifier) loadFromCache(gun data.GUN, tp trustpinning.TrustPinConfig) (*tuf.Repo, error) {
	repo, _, err := client.LoadTUFRepo(client.TUFLoadOptions{
		GUN:          gun,
		TrustPinning: tp,
		Cache:        v.cache,
		IgnoreExpiry: v.ignoreExpiry,
	})
	return repo, err
}

// loadTUFRepo just calls LoadTUFRepo with the right values.  It attempts to download
// metadata from the server into an in memory cache, and if successful copies that data
// to the actual cache (to avoid corruption if the download is interrupted).
// But if no remote is provided, it will just attempt to load from cache and nothing
// else.
func (v *verifier) loadTUFRepo(gun data.GUN, tp trustpinning.TrustPinConfig, remote storage.RemoteStore) (*tuf.Repo, error) {
	if remote == nil {
		return v.loadFromCache(gun, tp)
	}

	// Use an in memory cache first, so downloading doesn't necessarily corrupt
	// local state, since it's possible that connectivity issues will prevent
	// re-connecting to fix it.  Do not want a half-downloaded repo to corrupt
	// an already-complete cache.
	cache := storage.NewMemoryStore(nil)
	if err := copyCache(v.cache, cache); err != nil {
		return nil, err
	}

	// First we try to download from the server - this requires that the metadata
	// not be expired.  However, if we cannot contact the server, we fall back on
	// the cached metadata, which *may* be expired, depending on the configuration
	repo, _, err := client.LoadTUFRepo(client.TUFLoadOptions{
		GUN:                    gun,
		TrustPinning:           tp,
		RemoteStore:            remote,
		Cache:                  cache,
		AlwaysCheckInitialized: true,
	})
	switch err.(type) {
	case storage.ErrServerUnavailable, storage.NetworkError, storage.ErrOffline:
		var newErr error
		repo, newErr = v.loadFromCache(gun, tp)
		// If we get an offline error, that means that was some issue loading from
		// cache that should be in the logs.  But we should return the previous
		// server error
		if _, ok := newErr.(storage.ErrOffline); !ok {
			return repo, newErr
		}
	case nil:
		// There was no error - copy over the in memory cache to the local
		// disk cache. This is only best effort - if there are any io errors
		// when writing out the in memory cache, the local cache does get
		// corrupted.
		if err := copyCache(cache, v.cache); err != nil {
			return nil, err
		}
	}
	return repo, err
}

// VerifyImage takes an image reference (name, and tag and/or sha) and remote store
// and uses them and the pinned keys to determine whether the image is signed
// (and to populate the tag and digests if so)
func (v *verifier) VerifyImage(imageRef reference.Named, remote storage.RemoteStore) (reference.Canonical, error) {
	name := imageRef.Name()
	var tag string
	var imageDigest digest.Digest

	if i, ok := imageRef.(reference.Canonical); ok {
		imageDigest = i.Digest()
	}
	if i, ok := imageRef.(reference.Tagged); ok {
		tag = i.Tag()
	}
	// if there is neither a tag nor a digest, use "latest" as the tag
	if tag == "" && imageDigest == "" {
		tag = "latest"
	}

	// Use an in memory cache first, so downloading doesn't necessarily corrupt
	// local state, since it's possible that connectivity issues will prevent
	// re-connecting to fix it.  Do not want a half-downloaded repo to corrupt
	// an already-complete cache.
	cache := storage.NewMemoryStore(nil)
	if err := copyCache(v.cache, cache); err != nil {
		return nil, err
	}

	tp := trustpinning.TrustPinConfig{
		KeyIDs:      v.keyIDs,
		Certs:       v.certIDs,
		DisableTOFU: true,
	}
	repo, err := v.loadTUFRepo(data.GUN(name), tp, remote)
	if err != nil {
		return nil, notaryError(name, err)
	}

	r := client.NewReadOnly(repo)
	// If a tag is provided, just look up the metadata by tag and retrieve the
	// first signed image matching that tag.
	if tag != "" {
		tgt, err := r.GetTargetByName(tag, releasesRole, data.CanonicalTargetsRole)
		if err != nil {
			return nil, notaryError(name, err)
		}

		// Only get the tag if it's in the top level targets role or the releases delegation role
		// ignore it if it's in any other delegation roles
		if tgt.Role != releasesRole && tgt.Role != data.CanonicalTargetsRole {
			return nil, notaryError(name, storage.ErrMetaNotFound{})
		}

		_, tgtDigest, err := convertTarget(tgt.Target)
		if err != nil {
			return nil, err
		}
		if imageDigest != "" && imageDigest != tgtDigest {
			return nil, errors.Errorf("signed image for %s:%s does not match provided digest", name, tag)
		}
		return updateReference(imageRef, tag, tgtDigest)
	}

	// If no tag is provided, then a digest must be provided (since we check above for the lack
	// of both, and add "latest" as the tag if both are missing).  If so, we have to do a reverse
	// lookup of all the signed images, and find one that matches the digest.
	targets, err := r.ListTargets(releasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return nil, notaryError(name, err)
	}
	// convert the digest value to bytes so that we can compare bytes against a notary hash
	hexVal := imageDigest.Encoded()
	digestBytes, err := hex.DecodeString(hexVal)
	if err != nil {
		return nil, errors.New("invalid image digest provided")
	}
	for _, tgt := range targets {
		// Only get the tag if it's in the top level targets role or the releases delegation role
		// ignore it if it's in any other delegation roles
		if tgt.Role != releasesRole && tgt.Role != data.CanonicalTargetsRole {
			continue
		}

		// we found a match - return the tag name and the digest
		if bytes.Equal(digestBytes, tgt.Hashes[notary.SHA256]) {
			return updateReference(imageRef, tgt.Name, imageDigest)
		}
	}
	return nil, notaryError(name, client.ErrNoSuchTarget(imageDigest.String()))
}

func updateReference(ref reference.Named, tag string, d digest.Digest) (reference.Canonical, error) {
	updated, err := reference.WithTag(ref, tag)
	if err != nil {
		return nil, err
	}
	return reference.WithDigest(updated, d)
}

// notaryError formats an error message received from the notary service into a more
// friendly error message
func notaryError(repoName string, err error) error {
	switch e := err.(type) {
	case storage.ErrMetaNotFound, client.ErrRepositoryNotExist:
		return errors.Errorf("no trust data available for repository %s.", repoName)
	case *json.SyntaxError:
		return errors.Wrapf(err, "no trust data available for repository %s.", repoName)
	case storage.ErrServerUnavailable, storage.NetworkError, storage.ErrOffline:
		return errors.Wrap(err, "error contacting trust server")
	case trustpinning.ErrRootRotationFail, trustpinning.ErrValidationFail, signed.ErrInvalidKeyType:
		return errors.Wrapf(err, "potential malicious behavior - trust data mismatch for repository %s", repoName)
	case signed.ErrLowVersion:
		return errors.Wrapf(err, "potential malicious behavior - trust data version is lower than expected for remote repository %s", repoName)
	case signed.ErrRoleThreshold:
		return errors.Wrapf(err, "potential malicious behavior - trust data has insufficient signatures for remote repository %s", repoName)
	case client.ErrNoSuchTarget: // ErrNoSuchTarget is a string
		return errors.Wrapf(err, "no trust signature found for %s:%s", repoName, string(e))
	}
	return err
}

// Converts a notary target to an image digest and tag
func convertTarget(t client.Target) (string, digest.Digest, error) {
	d, ok := t.Hashes[notary.SHA256]
	if !ok {
		return "", "", errors.Errorf("trust data has no valid digest for %s", t.Name)
	}
	return t.Name, digest.NewDigestFromBytes(digest.SHA256, d), nil
}

func copyCache(from, to metaCache) error {
	for _, name := range from.ListFiles() {
		//Set() prepends a version to the name from the data, so strip any existing version
		l := strings.Split(name, ".")
		name = l[len(l)-1]
		metaBytes, err := from.GetSized(name, storage.NoSizeLimit)
		if err != nil {
			return err
		}
		if err := to.Set(name, metaBytes); err != nil {
			return err
		}
	}
	return nil
}
