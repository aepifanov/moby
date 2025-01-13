package telemetry

import (
	"context"
	"os"
	"strings"

	"github.com/docker/docker/libnetwork/resolvconf"
	"github.com/segmentio/analytics-go/v3"
)

// Allow overriding the resolv.conf path in tests.
type resolvconfPathCtxKey struct{}

func fillPlatformTraits(ctx context.Context, traits analytics.Traits) {
	traits.Set("dns_search_domains", getDNSSearchDomains(ctx))
}

func getDNSSearchDomains(ctx context.Context) any {
	rcPath := "/etc/resolv.conf"
	if p := ctx.Value(resolvconfPathCtxKey{}); p != nil {
		// Only used in testing. Let it panic if the type is wrong.
		rcPath = p.(string)
	}
	rc, err := os.ReadFile(rcPath)
	if err != nil {
		g(ctx).WithError(err).Debug("unable to get DNS search domains")
		return nil
	}
	domains := resolvconf.GetSearchDomains(rc)
	return strings.Join(domains, " ")
}
