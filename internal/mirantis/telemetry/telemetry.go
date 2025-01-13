package telemetry

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/containerd/log"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/daemon/cluster"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/dockerversion"
	"github.com/segmentio/analytics-go/v3"
)

var (
	pollPeriod = 24 * time.Hour

	// segmentToken is the API token we use for Segment.
	// The token set here is the staging-token, but will be replaced with the
	// production token at compile time using an -X compile flag, e.g.:
	// -ldflags "-X \"daemon.telemetry.segmentToken=<my-token>\""
	segmentToken = "MEMutJjWBF0qNOqd6pqTuDPvL07ZbHT1" // #nosec G101
)

func g(ctx context.Context) *log.Entry {
	return log.G(ctx).WithField("module", "telemetry")
}

// Telemetry is a handle to the telemetry sender
type Telemetry struct {
	cancel context.CancelFunc
	s      sysInfo
	c      clusterInfo
	client analytics.Client
	ticker *time.Ticker
}

type sysInfo interface {
	TrustMode() config.TrustMode
	SystemInfo(context.Context) (*system.Info, error)
	Features() map[string]bool
}

type clusterInfo interface {
	IsAgent() bool
	IsManager() bool
	Inspect() (swarm.Swarm, error)
}

type logAdapter struct {
	*log.Entry
}

func (l logAdapter) Logf(format string, args ...interface{}) {
	l.Entry.Infof(format, args...)
}

// Start will start sending telementry if not disabled
// Caller should call Stop on the returned object
func Start(ctx context.Context, s sysInfo, c *cluster.Cluster) *Telemetry {
	ctx, cancel := context.WithCancel(ctx)
	client, err := analytics.NewWithConfig(segmentToken, analytics.Config{
		Logger: logAdapter{g(ctx)},
	})
	if err != nil {
		panic(err) // All config is hardcoded; config errors can only be resolved with code changes.
	}
	t := &Telemetry{
		cancel: cancel,
		s:      s,
		c:      c,
		client: client,
		ticker: time.NewTicker(pollPeriod),
	}
	t.start(ctx)
	return t
}

func (t *Telemetry) start(ctx context.Context) {
	g(ctx).Debug("Docker daemon will send anonymous usage telemetry")
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.ticker.C:
				t.Send(ctx)
			}
		}
	}()
}

// Stop shuts down sending telemetry data
func (t *Telemetry) Stop() {
	t.cancel()
	t.ticker.Stop()
	_ = t.client.Close()
}

func (t *Telemetry) Send(ctx context.Context) {
	info, err := t.s.SystemInfo(context.Background())
	if err != nil {
		g(ctx).WithError(err).Debug("Error getting system info for telemetry")
		info = &system.Info{} // limp along, avoiding nil pointer dereference
	}
	f := t.s.Features()
	e, ok := f["telemetry"]
	// telemetry is enabled by default, if the value in Features is not set, or
	// if the value of features is set and is true
	enabled := !ok || e

	if !enabled {
		return
	}

	traits := analytics.Traits{
		"architecture":             info.Architecture,
		"commit":                   dockerversion.GitCommit,
		"edition_type":             "ee",
		"graphdriver":              info.Driver,
		"kernel":                   info.KernelVersion,
		"os":                       info.OperatingSystem,
		"os_type":                  info.OSType,
		"hostname":                 info.Name,
		"version":                  dockerversion.Version,
		"is_experimental":          info.ExperimentalBuild,
		"isolation":                info.Isolation,
		"live_restore":             info.LiveRestoreEnabled,
		"cpus":                     info.NCPU,
		"memory":                   info.MemTotal,
		"container_count":          info.Containers,
		"container_count_running":  info.ContainersRunning,
		"image_count":              info.Images,
		"fips_enabled":             slices.Contains(info.SecurityOptions, "name=fips"),
		"product_license":          info.ProductLicense,
		"mirantis_license_subject": info.MirantisLicenseSubj,
		"mirantis_license_source":  info.MirantisLicenseSrc,
		"security_options":         strings.Join(info.SecurityOptions, ","),
		"trust_mode":               t.s.TrustMode(),
	}
	if t.c != nil && (t.c.IsAgent() || t.c.IsManager()) {
		swarmInfo, err := t.c.Inspect()
		if err != nil {
			g(ctx).WithError(err).Debug("Error inspecting Swarm")
		} else {
			traits["swarm_cluster_id"] = swarmInfo.ID
		}
	}
	fillPlatformTraits(ctx, traits)
	identity := analytics.Identify{
		AnonymousId: fmt.Sprintf("%x", sha256.Sum256([]byte(info.ID))),
		Traits:      traits,
		Context:     &analytics.Context{Direct: true},
	}
	if err := t.client.Enqueue(identity); err != nil && !errors.Is(err, analytics.ErrClosed) {
		g(ctx).WithError(err).Error("Error enqueueing telemetry")
	}
}
