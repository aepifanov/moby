//go:build fipster
// +build fipster

package daemon

import "crypto/fips"

func init() {
	fipsEnabled = fips.Enabled()
}
