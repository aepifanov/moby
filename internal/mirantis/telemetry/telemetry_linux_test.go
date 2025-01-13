package telemetry

import (
	"context"
	"io"
	"testing"

	"github.com/containerd/log"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/segmentio/analytics-go/v3"
	"github.com/sirupsen/logrus"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

var platformTraitsToIgnore = map[string]bool{
	// Value taken from host's /etc/resolv.conf; unpredictable value.
	// Covered by a dedicated test.
	"dns_search_domains": true,
}

func ignorePlatformTraits() cmp.Option {
	return cmpopts.IgnoreMapEntries(func(k string, v any) bool {
		return platformTraitsToIgnore[k]
	})
}

func TestResolvConfTraits(t *testing.T) {
	tc := []struct {
		name          string
		filepath      string
		expectTrait   bool
		expectedValue any
	}{
		{
			name:          "ENOENT",
			filepath:      "testdata/does-not-exist",
			expectTrait:   true,
			expectedValue: nil,
		},
		{
			name:          "SearchDomains=no",
			filepath:      "testdata/resolv.conf.no-search-domains",
			expectTrait:   true,
			expectedValue: "",
		},
		{
			name:          "SearchDomains=yes",
			filepath:      "testdata/resolv.conf.with-search-domains",
			expectTrait:   true,
			expectedValue: "foo.example bar.example baz.example",
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
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

			ctx := log.WithLogger(context.Background(), logrus.NewEntry(logger))
			tel.Send(context.WithValue(ctx, resolvconfPathCtxKey{}, tt.filepath))
			dnsSearchTrait, ok := actual.Traits["dns_search_domains"]
			if assert.Check(t, is.Equal(ok, tt.expectTrait)) && tt.expectTrait {
				assert.Check(t, is.Equal(dnsSearchTrait, tt.expectedValue))
			}
		})
	}
}
