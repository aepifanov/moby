package config // import "github.com/docker/docker/daemon/config"
import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestValidateContentTrust(t *testing.T) {
	for _, validConfig := range []*ContentTrust{
		nil, // no error if content trust is not configured
		{ // Valid if only trust pinning official images is specified
			TrustPinning: TrustPinning{
				OfficialLibraryImages: true,
			},
		},
		{ // Valid if only trust pinning specific root keys is specified
			TrustPinning: TrustPinning{
				RootKeys: map[string][]string{
					"docker.io/library/alpine": {"key1"},
				},
			},
		},
		{ // Valid if all trust pinning options are specified
			TrustPinning: TrustPinning{
				RootKeys: map[string][]string{
					"docker.io/library/alpine": {"key1"},
				},
				OfficialLibraryImages: true,
			},
		},
	} {
		assert.Check(t, ValidateContentTrust(validConfig))

		// call Validate to make sure that Config has ContentTrust as a field
		// and that Validate calls ValidateContentTrust
		assert.Check(t, Validate(&Config{
			CommonConfig: CommonConfig{
				ContentTrust: validConfig,
			},
		}))
	}

	for _, invalidConfig := range []*ContentTrust{
		{}, // invalid if empty
		{ // invalid if trust pinning is empty
			TrustPinning: TrustPinning{
				RootKeys: map[string][]string{},
			},
		},
		// invalid if any of the root key values is empty
		{
			TrustPinning: TrustPinning{
				RootKeys: map[string][]string{
					"docker.io/library/alpine": nil,
				},
			},
		},
		{
			TrustPinning: TrustPinning{
				RootKeys: map[string][]string{
					"docker.io/library/busybox": {"key1"},
					"docker.io/library/alpine":  {},
				},
			},
		},
	} {
		err := ValidateContentTrust(invalidConfig)
		assert.Check(t, is.ErrorContains(err, "invalid content trust configuration"))

		// call Validate to make sure that Config has ContentTrust as a field
		// and that Validate calls ValidateContentTrust
		err = Validate(&Config{
			CommonConfig: CommonConfig{
				ContentTrust: invalidConfig,
			},
		})
		assert.Check(t, is.ErrorContains(err, "invalid content trust configuration"))
	}
}
