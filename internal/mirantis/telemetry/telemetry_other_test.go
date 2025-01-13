//go:build !linux

package telemetry

import (
	"context"
	"io"
	"testing"

	"github.com/containerd/log"
	"github.com/google/go-cmp/cmp"
	"github.com/segmentio/analytics-go/v3"
	"github.com/sirupsen/logrus"
	"gotest.tools/v3/assert"
)

func ignorePlatformTraits() cmp.Option {
	return nil
}

func TestPlatformTraitsAreUnset(t *testing.T) {
	var actual analytics.Identify
	tel := &Telemetry{
		s: mockInfoSource{},
		client: &testClient{
			segmentCB: func(msg analytics.Message) error {
				var ok bool
				actual, ok = msg.(analytics.Identify)
				assert.Assert(t, ok, "unexpected type for msg: %T", msg)
				return nil
			},
		},
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.TraceLevel)
	logger.AddHook(testingLogrusHook{t})
	tel.Send(log.WithLogger(context.Background(), logrus.NewEntry(logger)))

	for _, trait := range []string{
		"dns_search_domains",
	} {
		v, ok := actual.Traits[trait]
		assert.Check(t, !ok, "unexpected trait [%q: %q]", trait, v)
	}
}
