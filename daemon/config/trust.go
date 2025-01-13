package config // import "github.com/docker/docker/daemon/config"

import (
	"errors"
)

// NOTE - Intended for api/types, but moved to internal for EE 2.1

// This file contains the content trust configuration needed for engine
// signing configuration verification - this is an EE-only feature.
// See https://docs.google.com/document/d/10QBg63Hnpy1FFlmpZZnZ5YcD0GcmWl7vKKcYXhJ3yAQ

// TrustPinning specifies trusted root keys, if any, for validating signing metadata
type TrustPinning struct {
	// RootKeys specifies the canonical key IDs for the root keys used to sign
	// repositories.  This means that if data is signed with a different key than is
	// specified, trust validation will fail.  This data is expected to look like:
	// {
	// 	"my.registry.io/myorg/repo": ["keyid1", "keyid2"],
	// 	"my.registry.io/otherorg/*": ["keyid2"],
	// 	"my.registry.io/*": ["keyid3"],
	// 	"docker.io/myorg/*": ["keyid4"],
	// }
	// The most specific key IDs are chosen for a particular repo.  So for
	// my.registry.io/myorg/repo, either keyid1 or keyid2 can sign.
	RootKeys map[string][]string `json:"root-keys,omitempty"`

	// CertIDs specifies the certificate IDs associated with signed repositories.
	// Example:
	// {
	// 	"my.registry.io/myorg/repo": ["certid1", "certid2"],
	//	"docker.io/myorg/repo": ["certid3"],
	// }
	// Note that wildcards are not supported for repository names.
	CertIDs map[string][]string `json:"cert-ids,omitempty"`

	// OfficialLibraryImages specifies whether the engine should trust the
	// pinned root keys for docker.io/library/* - these are pinned in the engine
	// itself.  If a user specifies "docker.io/library/*" in the RootKeys field,
	// the user specification will take precedence over the engine's pinned keys.
	OfficialLibraryImages bool `json:"official-library-images,omitempty"`
}

// TrustMode specifies whether signature should be disabled, permissive or enforced.
// See ContentTrust.
type TrustMode string

const (
	// TrustModeDisabled indicates that no verifications will happen
	TrustModeDisabled TrustMode = "disabled"
	// TrustModePermissive makes verification warn if it fails
	TrustModePermissive TrustMode = "permissive"
	// TrustModeEnforced makes verification strictly enforced
	TrustModeEnforced TrustMode = "enforced"
)

// ContentTrust specifies the configuration for verifying signing - how trust is rooted,
// where the trust servers are, whether to enforce the policy or warn, whether to allow
// expired metadata, etc.
type ContentTrust struct {
	// TrustPinning specifies the trusted root keys for validating signing metadata.
	TrustPinning TrustPinning `json:"trust-pinning,omitempty"`

	// Mode specifies whether signature verification should be disabled, permissive
	// or enforced. Permissive mode will warn in the daemon logs if verifications fail
	// but will not prevent any operations, which is useful to monitor any content trust
	// issues that may arise. Once deemed ready, the configuration is to be set to
	// enforced mode.
	//
	// Defaults to disabled.
	Mode TrustMode `json:"mode,omitempty"`

	// AllowExpiredCachedTrustData may be necessary for devices which have intermittent
	// connectivity and may not be able to regularly download updated trust metdata.
	// This removes a security property (freshness) from content trust, but provides
	// better availability.  This only allows cached data to be expired - trust data that
	// is downloaded from a server still cannot be expired even if this is set to true.
	AllowExpiredCachedTrustData bool `json:"allow-expired-cached-trust-data,omitempty"`
}

// ValidateContentTrust ensures that the content trust configuration, if provided,
// will provide either pinned keys or specific servers from which trust metadata can be
// fetched.
func ValidateContentTrust(c *ContentTrust) error {
	if c == nil { // no content trust configuration is a valid configuration
		return nil
	}

	// no empty root key lists allowed (in the future, perhaps allowing them would allow
	// users to specify a richer configuration - e.g. these root keys for all repos that look
	// like this, *EXCEPT* for this one repo)
	for _, l := range c.TrustPinning.RootKeys {
		if len(l) == 0 {
			return errors.New("invalid content trust configuration - root key lists cannot be empty")
		}
	}

	// Some type of trust configuration must be set up - some specific server for
	// some images are configured, or trust pinning must be configured (either official
	/// images must be trusted or root key IDs must be provided)
	if !c.TrustPinning.OfficialLibraryImages && len(c.TrustPinning.RootKeys) == 0 && len(c.TrustPinning.CertIDs) == 0 {
		return errors.New("invalid content trust configuration - trust pinning cannot be empty")
	}

	return nil
}
