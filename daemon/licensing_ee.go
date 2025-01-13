package daemon

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/dockerversion"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	licenseNamePrefix = "com.docker.license"
	licenseFilename   = "docker.lic"
	defaultLicense    = "Unlicensed - not for production workloads"
	workerNodeLicense = "this node is not a swarm manager - check license status on a manager node"

	mirantisLicensePublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3WOM60JOLa4xBj8ZH91k
zEvvTWUOPyQNqF7PkR1oUx4VhiXBVi8wjlCxBE2KvITol69J9uB/PyJSeLKN1IXe
DYkmsNHRp+2nv5kh1hvptODQhhZC+gGV2wjQ76fNY8rCrVXN1NBwry8UPSbStOWG
a5WN59E+eBBslhehaeQL1vbrcWBfs6rA8wOHHvSc6zFbuPMVQF8T/FyLCwKFijvt
RNeeNsTQfGvXDPMkazRDo061K6UhPRWG01cBuqqOIudPdKqyPjKflKd05Ck4FCtO
SSvdB9xXgzfkCBt+Z/IRt9dEOatGVN7IN31iw6JgJGzxjQDRE/RDUQ7uoxL1c8vz
hQIDAQAB
-----END PUBLIC KEY-----
`
)

// clusterAPI gives us access to the swarm APIs for the licensing library
// The daemon/cluster packaqe can't be imported directly due to circular
// imports so this defines just the set of APIs needed by the licensing
// library to retrieve the swarm config stored license shared by UCP
type clusterAPI interface {
	GetNodes(options types.NodeListOptions) ([]swarm.Node, error)
	GetConfig(input string) (swarm.Config, error)
	GetConfigs(options types.ConfigListOptions) ([]swarm.Config, error)
	CreateConfig(s swarm.ConfigSpec) (string, error)
	UpdateConfig(input string, version uint64, spec swarm.ConfigSpec) error
}

// MirantisLicenseClaims extends the standard JWT claims, adding in private claims
// for licensing details.
type MirantisLicenseClaims struct {
	jwt.Claims
	Legacy struct {
		Dev    bool `json:"dev"`
		Limits struct {
			Clusters          int `json:"clusters"`
			WorkersPerCluster int `json:"workers_per_cluster"`
		} `json:"limits"`
	} `json:"license"`
}

// Human-readable string representation of a license claim.
func (c MirantisLicenseClaims) String() string {
	if c.Expiry == nil {
		return "Invalid license - no valid expiration"
	}

	expiration := c.Expiry.Time()
	expirationString := expiration.Format("2006-01-02")

	subj := c.Subject

	// Subject in jwt.Claims has omitempty
	if subj == "" {
		subj = "n/a"
	}

	err := c.Validate(jwt.Expected{
		Time: time.Now(),
	})

	if errors.Is(err, jwt.ErrExpired) {
		return fmt.Sprintf("Expired on %s for %s", expirationString, subj)
	}

	// it's extremely unlikely that we'll get ErrNotValidYet and also have a
	// nil NotBefore, but it's better to check and not crash
	if c.NotBefore != nil && errors.Is(err, jwt.ErrNotValidYet) {
		notBefore := c.NotBefore.Time()
		notBeforeString := notBefore.Format("2006-01-02")
		return fmt.Sprintf("Not valid until %s for %s", notBeforeString, subj)
	}

	return fmt.Sprintf("Valid until %s for %s", expirationString, subj)
}

// fillLicense populates the product license field(s) in the provided info
// type based on the available licensing.
func (daemon *Daemon) fillLicense(v *system.Info) {
	v.ProductLicense = dockerversion.DefaultProductLicense
	if v.ProductLicense == "" {
		v.ProductLicense = defaultLicense
	}
	v.MirantisLicenseSubj = ""

	// We just want a license -- doesn't matter from where.
	var loaders []licenseLoader

	// Licenses can only be found on swarm managers if the node is a swarm node.
	c := daemon.cluster
	if c != nil && c.IsAgent() {
		if !c.IsManager() {
			v.ProductLicense = workerNodeLicense
			return
		}
		loaders = append(loaders, loadLicenseCluster(c))
	}

	loaders = append(loaders, loadLicenseLocal(v.DockerRootDir))
	lic := loadLicense(loaders...)

	// No license available implies that the product is 'unlicensed'.
	if lic.data == nil {
		return
	}

	if err := fillEnterpriseLicenseMirantis(lic, v); err != nil {
		logrus.WithError(err).Error("Mirantis license failure")
	}
}

// loadMirantisLicensePublicKey loads a PKIX public key from a PEM slice.
func loadMirantisLicensePublicKey(keyPEM []byte) (interface{}, error) {
	pemBlock, _ := pem.Decode(keyPEM)
	if pemBlock == nil {
		return nil, errors.New("public key not in PEM format")
	}

	key, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse license public key")
	}

	return key, nil
}

// fillEnterpriseLicenseMirantis validates the provided licensing information as
// a JWT, and extracts the license details (JWT claims).  The details of the license
// are populated into the the provided Info type.
func fillEnterpriseLicenseMirantis(lic loadedLicense, v *system.Info) error {
	// process license format that has JWT embedded in a legacy json license
	var license struct {
		KeyID         string `yaml:"key_id" json:"key_id"`
		PrivateKey    string `yaml:"private_key" json:"private_key,omitempty"`
		Authorization string `yaml:"authorization" json:"authorization,omitempty"`

		JWT string `yaml:"jwt" json:"jwt,omitempty"`
	}

	jsonErr := json.Unmarshal(lic.data, &license)

	// Check for JWT field
	if jsonErr == nil && len(license.JWT) > 0 {
		lic.data = []byte(license.JWT)
	}

	token, err := jwt.ParseSigned(string(lic.data))
	if err != nil {
		return errors.Wrap(err, "failed to parse JWT")
	}

	loadedPublicKey, err := loadMirantisLicensePublicKey([]byte(mirantisLicensePublicKey))
	if err != nil {
		logrus.WithError(err).Error("Unable to parse static Mirantis public key")
	}

	// The Mirantis JWT claims are private alongside the standard/registered claims.
	claims := MirantisLicenseClaims{}
	if err := token.Claims(loadedPublicKey, &claims); err != nil {
		return errors.Wrap(err, "unable to process JWT license claims")
	}

	// NOTE: There is no enforcement of claims to runtime operation yet.  Only basic
	// license information is provided.

	v.ProductLicense = claims.String()
	v.MirantisLicenseSubj = claims.Subject
	v.MirantisLicenseSrc = lic.source

	return nil
}

// getLatestNamedConfig looks for versioned instances of configs with the
// given name prefix which have a `-NUM` integer version suffix. Returns the
// config with the highest version number found or nil if no such configs exist
// along with its version number.
func getLatestNamedConfig(capi clusterAPI, namePrefix string) (int, error) {
	latestVersion := -1
	// List any/all existing configs so that we create a newer version than
	// any that already exist.
	filter := filters.NewArgs()
	filter.Add("name", namePrefix)
	existingConfigs, err := capi.GetConfigs(types.ConfigListOptions{Filters: filter})
	if err != nil {
		return latestVersion, errors.Wrap(err, "unable to list existing configs")
	}

	for _, existingConfig := range existingConfigs {
		existingConfigName := existingConfig.Spec.Name
		nameSuffix := strings.TrimPrefix(existingConfigName, namePrefix)
		if nameSuffix == "" || nameSuffix[0] != '-' {
			continue // No version specifier?
		}

		versionSuffix := nameSuffix[1:] // Trim the version separator.
		existingVersion, err := strconv.Atoi(versionSuffix)
		if err != nil {
			continue // Unable to parse version as integer.
		}
		if existingVersion > latestVersion {
			latestVersion = existingVersion
		}
	}

	return latestVersion, nil
}

// licenseLoader functions load license bytes from some source.
//
// Implementations signal that the source does not contain license data
// by returning a loadedLicence value where data is nil.
// It is not an error for the source to not contain license data.
// The error return value is reserved for exceptional errors
// which prevent the license data from being loaded,
// e.g. EPERM when trying to read the license from a file.
type licenseLoader func() (loadedLicense, error)

// loadedLicense is the result of loading a license from a source.
type loadedLicense struct {
	// The raw license bytes loaded, or nil if no license was loaded.
	data []byte
	// The source of the data, e.g. "swarm-config" or "local-file".
	// Only guaranteed to be set when data is not nil.
	source string
}

// loadLicense will attempt to load a license from the collection of provided
// license loaders.  Any errors occurring during loading are logged, and processing
// continues to the next loader.  Processing ends when a license loader returns
// license bytes.
func loadLicense(loaders ...licenseLoader) loadedLicense {
	for _, loader := range loaders {
		lic, err := loader()
		if lic.data != nil {
			return lic
		}

		if err != nil {
			logrus.WithError(err).Warn("Unexpected error loading license")
		}
	}

	return loadedLicense{}
}

func licenseLoadError(err error) (loadedLicense, error) {
	return loadedLicense{}, err
}

// loadLicenseCluster asserts various preconditions against the cluster/swarm prior to querying
// the cluster API for a license.
func loadLicenseCluster(c Cluster) licenseLoader {
	return func() (loadedLicense, error) {
		if c == nil {
			return licenseLoadError(errors.New("unable to lookup licensing details on Swarm without a daemon.cluster"))
		}

		capi, ok := c.(clusterAPI)
		if !ok {
			return licenseLoadError(errors.New("daemon.cluster type cast failure during Swarm license lookup"))
		}

		// Load the latest license index
		latestVersion, err := getLatestNamedConfig(capi, licenseNamePrefix)
		if err != nil {
			return licenseLoadError(errors.Wrap(err, "unable to check Swarm configs for license"))
		}

		if latestVersion >= 0 {
			cfg, err := capi.GetConfig(fmt.Sprintf("%s-%d", licenseNamePrefix, latestVersion))
			if err != nil {
				return licenseLoadError(errors.Wrap(err, "unable to load license from swarm config"))
			}

			return loadedLicense{
				data:   cfg.Spec.Data,
				source: "swarm-config",
			}, nil
		}

		return loadedLicense{}, nil
	}
}

// loadLicenseLocal loads a license from a filesystem path.
func loadLicenseLocal(licensePath string) licenseLoader {
	return func() (loadedLicense, error) {
		data, err := os.ReadFile(filepath.Join(licensePath, licenseFilename))
		if err != nil {
			// The license file not existing is not something we need to error about - the
			// lack of a license is enough.
			if os.IsNotExist(err) {
				return loadedLicense{}, nil
			}

			return licenseLoadError(errors.Wrap(err, "unable to load license from local file"))
		}

		return loadedLicense{
			data:   data,
			source: "local-file",
		}, nil
	}
}
