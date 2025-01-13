package telemetry

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/containerd/log"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/dockerversion"
	"github.com/segmentio/analytics-go/v3"
	"github.com/sirupsen/logrus"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

type mockInfoSource struct {
	sysInfoCB      func() (*system.Info, error)
	getTrustModeCB func() config.TrustMode
	features       map[string]bool
}

func (m mockInfoSource) SystemInfo(context.Context) (*system.Info, error) {
	if m.sysInfoCB == nil {
		return nil, errors.New("sysInfoCB not set in test")
	}
	return m.sysInfoCB()
}

func (m mockInfoSource) TrustMode() config.TrustMode {
	if m.getTrustModeCB == nil {
		return ""
	}
	return m.getTrustModeCB()
}

func (m mockInfoSource) Features() map[string]bool {
	return m.features
}

type mockClusterSource struct {
	manager, agent bool
	inspectCB      func() (swarm.Swarm, error)
}

func (m mockClusterSource) IsAgent() bool {
	return m.agent
}

func (m mockClusterSource) IsManager() bool {
	return m.manager
}

func (m mockClusterSource) Inspect() (swarm.Swarm, error) {
	if m.inspectCB == nil {
		return swarm.Swarm{}, errors.New("inspectCB not set in test")
	}
	return m.inspectCB()
}

type testClient struct {
	segmentCB func(analytics.Message) error
}

func (c *testClient) Enqueue(msg analytics.Message) error {
	return c.segmentCB(msg)
}

func (*testClient) Close() error {
	return nil
}

type testingLogrusHook struct {
	t testing.TB
}

func (h testingLogrusHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h testingLogrusHook) Fire(entry *logrus.Entry) error {
	msg, err := entry.String()
	if err != nil {
		h.t.Logf("[format err=%v] %#v", err, entry)
	} else {
		h.t.Log(msg)
	}
	return nil
}

func TestTelemetryHappyPath(t *testing.T) {
	pollPeriod = 5 * time.Millisecond
	ticker := time.NewTicker(pollPeriod)
	trustMode := config.TrustMode("test")
	info := &system.Info{
		Architecture:       "architecture",
		Driver:             "driver",
		KernelVersion:      "kernel version",
		OperatingSystem:    "operating system",
		OSType:             "os type",
		Name:               "host name",
		ExperimentalBuild:  true,
		Isolation:          "isolation",
		LiveRestoreEnabled: true,
		NCPU:               2,
		MemTotal:           1234,
		Containers:         42,
		Images:             84,
		ProductLicense:     "subject test",
		SecurityOptions:    []string{"name=test", "name=selinux", "name=fips"},
	}
	expectedTraits := analytics.Traits{
		"architecture":            info.Architecture,
		"graphdriver":             info.Driver,
		"kernel":                  info.KernelVersion,
		"os":                      info.OperatingSystem,
		"os_type":                 info.OSType,
		"hostname":                info.Name,
		"is_experimental":         info.ExperimentalBuild,
		"isolation":               info.Isolation,
		"live_restore":            info.LiveRestoreEnabled,
		"version":                 dockerversion.Version,
		"commit":                  dockerversion.GitCommit,
		"edition_type":            "ee",
		"cpus":                    info.NCPU,
		"memory":                  info.MemTotal,
		"container_count":         info.Containers,
		"container_count_running": info.ContainersRunning,
		"image_count":             info.Images,
		"fips_enabled":            true,
		"product_license":         info.ProductLicense,
		"security_options":        strings.Join(info.SecurityOptions, ","),
		"trust_mode":              trustMode,
	}
	var actual analytics.Message

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.TraceLevel)
	logger.AddHook(testingLogrusHook{t})
	ctx, cancel := context.WithCancel(log.WithLogger(context.Background(), logrus.NewEntry(logger)))
	doneCh := make(chan struct{})
	tel := &Telemetry{
		cancel: cancel,
		s: mockInfoSource{
			sysInfoCB: func() (*system.Info, error) {
				return info, nil
			},
			getTrustModeCB: func() config.TrustMode {
				return trustMode
			},
		},
		ticker: ticker,
	}
	tel.client = &testClient{
		segmentCB: func(msg analytics.Message) error {
			tel.Stop()
			actual = msg
			close(doneCh)
			return nil
		},
	}
	tel.start(ctx)
	select {
	case <-ctx.Done():
	case <-doneCh:
	}
	assert.DeepEqual(t, actual.(analytics.Identify).Traits, expectedTraits, ignorePlatformTraits())
}

func TestSwarmClusterID(t *testing.T) {
	tc := []struct {
		name           string
		agent, manager bool
		info           *swarm.ClusterInfo
		expectTrait    bool
		expectedValue  any
	}{
		{
			name:        "SwarmNode=no",
			expectTrait: false,
		},
		{
			name:          "SwarmNode=worker",
			agent:         true,
			info:          &swarm.ClusterInfo{ID: "cluster-id"},
			expectTrait:   true,
			expectedValue: "cluster-id",
		},
		{
			name:          "SwarmNode=manager",
			manager:       true,
			info:          &swarm.ClusterInfo{ID: "cluster-id"},
			expectTrait:   true,
			expectedValue: "cluster-id",
		},
		{
			name:        "SwarmNode=worker/InspectError",
			agent:       true,
			expectTrait: false,
		},
		{
			name:        "SwarmNode=manager/InspectError",
			manager:     true,
			expectTrait: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			var actual analytics.Identify
			tel := &Telemetry{
				s: mockInfoSource{},
				c: mockClusterSource{
					manager: tt.manager,
					agent:   tt.agent,
					inspectCB: func() (swarm.Swarm, error) {
						if !tt.agent && !tt.manager {
							t.Error("Inspect() called on non-swarm node")
						}
						if tt.info == nil {
							return swarm.Swarm{}, errors.New("mock")
						}
						return swarm.Swarm{ClusterInfo: *tt.info}, nil
					},
				},
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
			clusterIDTrait, ok := actual.Traits["swarm_cluster_id"]
			if assert.Check(t, is.Equal(ok, tt.expectTrait)) && tt.expectTrait {
				assert.Check(t, is.Equal(clusterIDTrait, tt.expectedValue))
			}
		})
	}
}
