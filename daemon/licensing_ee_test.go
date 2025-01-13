package daemon // import "github.com/docker/docker/daemon"

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/system"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2/jwt"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

var (
	legacyLicenseExpired = []byte(`{"key_id":"irlYm3b9fdD8hMUXjazF39im7VQSSbAm9tfHK8cKUxJt","private_key":"aH5tTRDAVJpCRS2CRetTQVXIKgWUPfoCHODhDvNPvAbz","authorization":"ewogICAicGF5bG9hZCI6ICJleUpsZUhCcGNtRjBhVzl1SWpvaU1qQXhPQzB3TXkweE9GUXdOem93TURvd01Gb2lMQ0owYjJ0bGJpSTZJbkZtTVMxMlVtRmtialp5YjFaMldXdHJlVXN4VFdKMGNGUmpXR1ozVjA4MVRWZFFTM2cwUnpJd2NIYzlJaXdpYldGNFJXNW5hVzVsY3lJNk1Td2ljMk5oYm01cGJtZEZibUZpYkdWa0lqcDBjblZsTENKc2FXTmxibk5sVkhsd1pTSTZJazltWm14cGJtVWlMQ0owYVdWeUlqb2lVSEp2WkhWamRHbHZiaUo5IiwKICAgInNpZ25hdHVyZXMiOiBbCiAgICAgIHsKICAgICAgICAgImhlYWRlciI6IHsKICAgICAgICAgICAgImp3ayI6IHsKICAgICAgICAgICAgICAgImUiOiAiQVFBQiIsCiAgICAgICAgICAgICAgICJrZXlJRCI6ICJKN0xEOjY3VlI6TDVIWjpVN0JBOjJPNEc6NEFMMzpPRjJOOkpIR0I6RUZUSDo1Q1ZROk1GRU86QUVJVCIsCiAgICAgICAgICAgICAgICJraWQiOiAiSjdMRDo2N1ZSOkw1SFo6VTdCQToyTzRHOjRBTDM6T0YyTjpKSEdCOkVGVEg6NUNWUTpNRkVPOkFFSVQiLAogICAgICAgICAgICAgICAia3R5IjogIlJTQSIsCiAgICAgICAgICAgICAgICJuIjogInlkSXktbFU3bzdQY2VZLTQtcy1DUTVPRWdDeUY4Q3hJY1FJV3VLODRwSWlaY2lZNjczMHlDWW53TFNLVGx3LVU2VUNfUVJlV1Jpb01OTkU1RHM1VFlFWGJHRzZvbG0ycWRXYkJ3Y0NnLTJVVUhfT2NCOVd1UDZnUlBIcE1GTXN4RHpXd3ZheThKVXVIZ1lVTFVwbTFJdi1tcTdscDVuUV9SeHJUMEtaUkFRVFlMRU1FZkd3bTNoTU9fZ2VMUFMtaGdLUHRJSGxrZzZfV2NveFRHb0tQNzlkX3dhSFl4R05sN1doU25laUJTeGJwYlFBS2syMWxnNzk4WGI3dlp5RUFURE1yUlI5TWVFNkFkajVISnBZM0NveVJBUENtYUtHUkNLNHVvWlNvSXUwaEZWbEtVUHliYncwMDBHTy13YTJLTjhVd2dJSW0waTVJMXVXOUdrcTR6akJ5NXpoZ3F1VVhiRzliV1BBT1lycTVRYTgxRHhHY0JsSnlIWUFwLUREUEU5VEdnNHpZbVhqSm54WnFIRWR1R3FkZXZaOFhNSTB1a2ZrR0lJMTR3VU9pTUlJSXJYbEVjQmZfNDZJOGdRV0R6eHljWmVfSkdYLUxBdWF5WHJ5clVGZWhWTlVkWlVsOXdYTmFKQi1rYUNxejVRd2FSOTNzR3ctUVNmdEQwTnZMZTdDeU9ILUU2dmc2U3RfTmVUdmd2OFluaENpWElsWjhIT2ZJd05lN3RFRl9VY3o1T2JQeWttM3R5bHJOVWp0MFZ5QW10dGFjVkkyaUdpaGNVUHJtazRsVklaN1ZEX0xTVy1pN3lvU3VydHBzUFhjZTJwS0RJbzMwbEpHaE9fM0tVbWwyU1VaQ3F6SjF5RW1LcHlzSDVIRFc5Y3NJRkNBM2RlQWpmWlV2TjdVIgogICAgICAgICAgICB9LAogICAgICAgICAgICAiYWxnIjogIlJTMjU2IgogICAgICAgICB9LAogICAgICAgICAic2lnbmF0dXJlIjogIm5saTZIdzRrbW5KcTBSUmRXaGVfbkhZS2VJLVpKenM1U0d5SUpDakh1dWtnVzhBYklpVzFZYWJJR2NqWUt0QTY4dWN6T1hyUXZreGxWQXJLSlgzMDJzN0RpbzcxTlNPRzJVcnhsSjlibDFpd0F3a3ZyTEQ2T0p5MGxGLVg4WnRabXhPVmNQZmwzcmJwZFQ0dnlnWTdNcU1QRXdmb0IxTmlWZDYyZ1cxU2NSREZZcWw3R0FVaFVKNkp4QU15VzVaOXl5YVE0NV8wd0RMUk5mRjA5YWNXeVowTjRxVS1hZjhrUTZUUWZUX05ERzNCR3pRb2V3cHlEajRiMFBHb0diOFhLdDlwekpFdEdxM3lQM25VMFFBbk90a2gwTnZac1l1UFcyUnhDT3lRNEYzVlR3UkF2eF9HSTZrMVRpYmlKNnByUWluUy16Sjh6RE8zUjBuakE3OFBwNXcxcVpaUE9BdmtzZFNSYzJDcVMtcWhpTmF5YUhOVHpVNnpyOXlOZHR2S0o1QjNST0FmNUtjYXNiWURjTnVpeXBUNk90LUtqQ2I1dmYtWVpnc2FRNzJBdFBhSU4yeUpNREZHbmEwM0hpSjMxcTJRUlp5eTZrd3RYaGtwcDhTdEdIcHYxSWRaV09SVWttb0g5SFBzSGk4SExRLTZlM0tEY2x1RUQyMTNpZnljaVhtN0YzdHdaTTNHeDd1UXR1SldHaUlTZ2Z0QW9lVjZfUmI2VThkMmZxNzZuWHYxak5nckRRcE5waEZFd2tCdGRtZHZ2THByZVVYX3BWangza1AxN3pWbXFKNmNOOWkwWUc4WHg2VmRzcUxsRXUxQ2Rhd3Q0eko1M3VHMFlKTjRnUDZwc25yUS1uM0U1aFdlMDJ3d3dBZ3F3bGlPdmd4V1RTeXJyLXY2eDI0IiwKICAgICAgICAgInByb3RlY3RlZCI6ICJleUptYjNKdFlYUk1aVzVuZEdnaU9qRTNNeXdpWm05eWJXRjBWR0ZwYkNJNkltWlJJaXdpZEdsdFpTSTZJakl3TVRjdE1EVXRNRFZVTWpFNk5UYzZNek5hSW4wIgogICAgICB9CiAgIF0KfQ=="}`)

	mirantisLicenseNotValid     = []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1ODIxNTk0NzgsImV4cCI6MTYxMzY5NTQ3NiwiYXVkIjoiIiwic3ViIjoiYXV0aDB8NWRjZmM0NDBlYWUyNWQwZWQ1NDZmNjgwIiwibGljZW5zZSI6IntcImRldlwiOiB0cnVlLCAgICAgXCJsaW1pdHNcIjogeyAgICAgICBcImNsdXN0ZXJzXCI6IDAsICAgICAgIFwid29ya2Vyc19wZXJfY2x1c3RlclwiOiAwICAgICB9fSJ9.Ocno5HSGhN7zycPkDBFJAdpYErV6lROwguZmilqzLwk")
	mirantisLicenseValidExpired = []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTEzOTU5OTEsImlhdCI6MTU4MjkzMTk5MSwic3ViIjoiZGV2fHRlc3QiLCJsaWNlbnNlIjp7ImRldiI6ZmFsc2UsImxpbWl0cyI6eyJjbHVzdGVycyI6MCwid29ya2Vyc19wZXJfY2x1c3RlciI6MH19LCJ1Y3AiOnsibWF4RW5naW5lcyI6MTAsInRpZXIiOiJQcm9kdWN0aW9uIiwibGljZW5zZVR5cGUiOiJPZmZsaW5lIiwic2Nhbm5pbmdFbmFibGVkIjp0cnVlfX0.VABV4loRvoK4PlY_tCdzmCoIcpiNEGBwt7albUsilUV1eJeVX0mdoXVrbUlCQJmkjbueg7AcwefX3HC7U37qLcfUJvZAwBvwvMJXMeTrua8DbmuXEK8twWTuA_t2hc2Fw1_M9ONCB4nO6Y2Q7Gr9Z96Yy5XQ7sRBv3_sL9ZHxuMWsL-9lgKSQjeF6wUaoFEZgptpnyGNFsEEDaC6aYS2mVRmhbXpD2DUpJb4Xb8lQ7xOmqfCMqsla3-OBpcfwIUOuXhCfzi8KV4-RMnKuYyCkORfU_ZcJVZvM90K2g9sgD-LsWnK2e_MeNr1m-VPYt6o6jcYkZcv3k_w4DBbM4Uz7g")
)

type testCluster struct {
	Cluster
	clusterAPI

	isAgent    bool
	isManager  bool
	getConfig  func(string) (swarm.Config, error)
	getConfigs func(types.ConfigListOptions) ([]swarm.Config, error)
}

func newTestCluster(swarmEnabled bool) *testCluster {
	return &testCluster{
		isAgent:    swarmEnabled,
		isManager:  swarmEnabled,
		getConfig:  func(s string) (swarm.Config, error) { return swarm.Config{}, nil },
		getConfigs: func(options types.ConfigListOptions) ([]swarm.Config, error) { return nil, nil },
	}
}

func (c *testCluster) IsAgent() bool {
	return c.isAgent
}

func (c *testCluster) IsManager() bool {
	return c.isManager
}

func (c *testCluster) GetConfig(input string) (swarm.Config, error) {
	return c.getConfig(input)
}

func (c *testCluster) GetConfigs(options types.ConfigListOptions) ([]swarm.Config, error) {
	return c.getConfigs(options)
}

// Ensures that if a license cannot be read the proper unlicensed text is populated.
func TestFillLicense_noLicense(t *testing.T) {
	tmpDir := t.TempDir()
	cluster := newTestCluster(true)
	d := &Daemon{root: tmpDir, cluster: cluster}
	v := &system.Info{DockerRootDir: tmpDir}
	v.Swarm.ControlAvailable = false

	assert.Equal(t, v.ProductLicense, "")
	assert.Equal(t, v.MirantisLicenseSubj, "")

	d.fillLicense(v)

	assert.Assert(t, is.Contains(v.ProductLicense, "Unlicensed"))
	assert.Equal(t, v.MirantisLicenseSubj, "")
}

// Ensures that legacy licenses are not supported.
func TestFillLicense_legacyLicenseExpired(t *testing.T) {
	tmpDir := t.TempDir()
	licenseFileName := filepath.Join(tmpDir, licenseFilename)
	err := os.WriteFile(licenseFileName, legacyLicenseExpired, 0644)
	assert.NilError(t, err)

	cluster := newTestCluster(true)
	d := &Daemon{root: tmpDir, cluster: cluster}
	v := &system.Info{DockerRootDir: tmpDir}
	v.Swarm.ControlAvailable = true

	assert.Equal(t, "", v.ProductLicense)

	d.fillLicense(v)

	assert.Assert(t, is.Contains(v.ProductLicense, "Unlicensed"))
	assert.Equal(t, v.MirantisLicenseSubj, "")
}

// Ensures that only license interrogation is performed on swarm manager nodes.
func TestFillLicense_nonSwarmManager(t *testing.T) {
	tmpDir := t.TempDir()
	licenseFileName := filepath.Join(tmpDir, licenseFilename)
	err := os.WriteFile(licenseFileName, mirantisLicenseValidExpired, 0644)
	assert.NilError(t, err)

	cluster := newTestCluster(false)
	d := &Daemon{root: tmpDir, cluster: cluster}
	v := &system.Info{DockerRootDir: tmpDir}
	v.Swarm.ControlAvailable = true
	cluster.isAgent = true

	assert.Equal(t, "", v.ProductLicense)

	d.fillLicense(v)

	assert.Assert(t, is.Contains(v.ProductLicense, "not a swarm manager"))
}

// Ensures that loading a Mirantis public key that is not in PEM format
// fails accordingly.
func TestLoadMirantisLicensePublicKey_failureNotPEM(t *testing.T) {
	key, err := loadMirantisLicensePublicKey([]byte("notapempublickey"))
	assert.Assert(t, is.Nil(key))
	assert.Assert(t, err != nil)
}

// Ensures that loading a Mirantis public key is in PEM format, but has
// bad ASN.1 structure fails accordingly.
func TestLoadMirantisLicensePublicKey_failureBadASN1(t *testing.T) {
	badKey := `-----BEGIN PUBLIC KEY-----
bm90YXB1YmxpY2tleQo=
-----END PUBLIC KEY-----
`
	key, err := loadMirantisLicensePublicKey([]byte(badKey))
	assert.Assert(t, is.Nil(key))
	assert.ErrorContains(t, err, "unable to parse")
}

// Ensures that a missing expiration date results in the appropriate
// invalid license string returned.
func TestMirantisLicenseClaims_missingExpiry(t *testing.T) {
	details := MirantisLicenseClaims{}.String()
	assert.Assert(t, is.Contains(details, "Invalid"))
}

// Ensures that product license details string creation creates the appropriate
// string contents based on expiration.
func TestMirantisLicenseClaims_expiration(t *testing.T) {
	runner := func(yearsDelta int, expected string) func(t *testing.T) {
		return func(t *testing.T) {
			now := time.Now()

			claims := MirantisLicenseClaims{}
			claims.Expiry = jwt.NewNumericDate(now.AddDate(yearsDelta, 0, 0))

			details := claims.String()
			assert.Assert(t, is.Contains(details, expected))
		}
	}

	t.Run("expired", runner(-1, "Expired"))
	t.Run("not-expired", runner(1, "Valid"))
}

// Ensures that a bogus Mirantis license fails to parse.
func TestFillLicenseMirantis_badLicenseParse(t *testing.T) {
	v := &system.Info{}

	err := fillEnterpriseLicenseMirantis(loadedLicense{data: legacyLicenseExpired}, v)
	assert.ErrorContains(t, err, "failed to parse")
}

// Ensures that a Mirantis license that is considered invalid fails verification.
func TestFillLicenseMirantis_badLicenseVerify(t *testing.T) {
	v := &system.Info{}

	err := fillEnterpriseLicenseMirantis(loadedLicense{data: mirantisLicenseNotValid}, v)
	assert.ErrorContains(t, err, "unable to process")
}

// Ensures that a Mirantis license that is valid (but expired) can be properly
// loaded.
func TestFillLicenseMirantis_validExpired(t *testing.T) {
	v := &system.Info{}
	assert.Assert(t, v.ProductLicense == "")

	const source = "mock-source"
	err := fillEnterpriseLicenseMirantis(loadedLicense{data: mirantisLicenseValidExpired, source: source}, v)
	assert.Assert(t, is.Nil(err))
	assert.Assert(t, is.Contains(v.ProductLicense, "Expired"))
	assert.Assert(t, is.Equal(v.MirantisLicenseSrc, source))
}

// Covers the scenario where a configuration is not present, and that default
// values are returned.
func TestGetLatestNamedConfig_noConfig(t *testing.T) {
	capi := newTestCluster(false)

	ver, err := getLatestNamedConfig(capi, licenseNamePrefix)
	assert.Equal(t, -1, ver)
	assert.NilError(t, err)
}

// Covers the scenario of an error being returned when accessing the cluster API,
// resulting in default values returned.
func TestGetLatestNamedConfig_getConfigsError(t *testing.T) {
	capi := newTestCluster(false)
	capi.getConfigs = func(options types.ConfigListOptions) ([]swarm.Config, error) {
		return nil, errors.New("intentional")
	}

	ver, err := getLatestNamedConfig(capi, licenseNamePrefix)
	assert.Equal(t, -1, ver)
	assert.Error(t, err, "unable to list existing configs: intentional")
}

// Covers the scenario of bad name suffixes being present in the response back from
// the cluster API.  Only the valid configuration should be available.
func TestGetLatestNamedConfig_badNameSuffix(t *testing.T) {
	capi := newTestCluster(false)
	capi.getConfigs = func(options types.ConfigListOptions) ([]swarm.Config, error) {
		return []swarm.Config{
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "",
					},
				},
			},
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "noversion",
					},
				},
			},
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "com.docker.license-badversion",
					},
				},
			},
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "com.docker.license-555",
					},
				},
			},
		}, nil
	}

	ver, err := getLatestNamedConfig(capi, licenseNamePrefix)
	assert.Equal(t, 555, ver)
	assert.NilError(t, err)
}

// Covers the scenario of when unordered configuration names are returned, only the
// latest version is returned (as identified by its version number suffix)
func TestGetLatestNamedConfig_latestVersion(t *testing.T) {
	capi := newTestCluster(false)
	capi.getConfigs = func(options types.ConfigListOptions) ([]swarm.Config, error) {
		return []swarm.Config{
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "com.docker.license-222",
					},
				},
			},
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "com.docker.license-555",
					},
				},
			},
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "com.docker.license-111",
					},
				},
			},
		}, nil
	}

	ver, err := getLatestNamedConfig(capi, licenseNamePrefix)
	assert.Equal(t, 555, ver)
	assert.NilError(t, err)
}

// Ensures that if no cluster is provided that the loadLicenseCluster
// function errors appropriately.
func TestLoadLicenseCluster_noCluster(t *testing.T) {
	loader := loadLicenseCluster(nil)
	lic, err := loader()

	assert.Assert(t, is.Nil(lic.data))
	assert.Assert(t, err != nil)
}

// Ensures that a proper clusterAPI instance is provided.
func TestLoadLicenseCluster_notClusterAPI(t *testing.T) {
	c := struct {
		Cluster
	}{}

	loader := loadLicenseCluster(c)
	lic, err := loader()

	assert.Assert(t, is.Nil(lic.data))
	assert.Assert(t, err != nil)
}

// Ensures that if getLatestNamedConfig() returns an error during cluster
// license loading that it is propagated.
func TestLoadLicenseCluster_getLatestNamedConfigError(t *testing.T) {
	c := newTestCluster(true)
	c.getConfigs = func(options types.ConfigListOptions) ([]swarm.Config, error) {
		return nil, errors.New("intentional")
	}

	loader := loadLicenseCluster(c)
	lic, err := loader()

	assert.Assert(t, is.Nil(lic.data))
	assert.Assert(t, err != nil)
}

// Ensures that if getLatestNamedConfig() returns available configurations, however
// the retrieving of them via getConfig() fails, that the error is propagated.
func TestLoadLicenseCluster_getConfigError(t *testing.T) {
	c := newTestCluster(true)

	// With swarm and with a valid license stored in config
	c.getConfigs = func(options types.ConfigListOptions) ([]swarm.Config, error) {
		return []swarm.Config{
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "com.docker.license-1",
					},
				},
			},
		}, nil
	}

	c.getConfig = func(s string) (swarm.Config, error) {
		return swarm.Config{}, errors.New("intentional")
	}

	loader := loadLicenseCluster(c)
	lic, err := loader()

	assert.Assert(t, is.Nil(lic.data))
	assert.Assert(t, err != nil)
}

// Ensures if the backing store has no configurations, the run is still successful.
func TestLoadLicenseCluster_noConfigs(t *testing.T) {
	c := newTestCluster(true)
	c.getConfigs = func(options types.ConfigListOptions) ([]swarm.Config, error) {
		return []swarm.Config{}, nil
	}

	loader := loadLicenseCluster(c)
	lic, err := loader()

	assert.Assert(t, is.Nil(lic.data))
	assert.Assert(t, is.Nil(err))
}

// Ensures that the happy path of an active cluster with a license configured (but expired)
// returns appropriately.
func TestLoadLicenseCluster_happyHasLicense(t *testing.T) {
	c := newTestCluster(true)

	// With swarm and with a valid license stored in config
	c.getConfigs = func(options types.ConfigListOptions) ([]swarm.Config, error) {
		return []swarm.Config{
			{
				Spec: swarm.ConfigSpec{
					Annotations: swarm.Annotations{
						Name: "com.docker.license-1",
					},
				},
			},
		}, nil
	}

	c.getConfig = func(s string) (swarm.Config, error) {
		return swarm.Config{
			Spec: swarm.ConfigSpec{
				Annotations: swarm.Annotations{
					Name: "com.docker.license-1",
				},
				Data: mirantisLicenseValidExpired,
			},
		}, nil
	}

	loader := loadLicenseCluster(c)
	lic, err := loader()

	assert.Assert(t, lic.data != nil)
	assert.Assert(t, is.Nil(err))
	assert.Assert(t, is.Equal(lic.source, "swarm-config"))
}

// Ensures that the local license loader returns the appropriate error
// if no license exists.
func TestLoadLicenseLocal_noLicense(t *testing.T) {
	tmpDir := t.TempDir()
	loader := loadLicenseLocal(tmpDir)
	lic, err := loader()

	assert.Assert(t, is.Nil(lic.data))
	assert.Assert(t, is.Nil(err))
}

// Ensures that the local license loader can read a license in the
// appropriate directory without error.
func TestLoadLicenseLocal_happyWithLicense(t *testing.T) {
	tmpDir := t.TempDir()
	licenseFileName := filepath.Join(tmpDir, licenseFilename)
	err := os.WriteFile(licenseFileName, mirantisLicenseValidExpired, 0644)
	assert.NilError(t, err)

	loader := loadLicenseLocal(tmpDir)
	lic, err := loader()

	assert.Assert(t, lic.data != nil)
	assert.Assert(t, is.Nil(err))
	assert.Assert(t, is.Equal(lic.source, "local-file"))
}
