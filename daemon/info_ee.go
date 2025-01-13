package daemon

import (
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/daemon/trust"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/opencontainers/selinux/go-selinux"
)

func (daemon *Daemon) TrustMode() config.TrustMode {
	return trust.Mode(daemon.config().Config.ContentTrust)
}

// fillSecurityLabels adds Docker EE specific labels and options to info
func (daemon *Daemon) fillSecurityLabels(v *system.Info, sysInfo *sysinfo.SysInfo, cfg *config.Config) {
	labels := v.Labels

	if sysInfo.AppArmor {
		labels = append(labels, "com.docker.security.apparmor=enabled")
	}
	if sysInfo.Seccomp && supportsSeccomp {
		labels = append(labels, "com.docker.security.seccomp=enabled") // leave full path out of labels
	}
	if selinux.GetEnabled() {
		labels = append(labels, "com.docker.security.selinux=enabled")
	}
	rootIDs := daemon.idMapping.RootPair()
	if rootIDs.UID != 0 || rootIDs.GID != 0 {
		labels = append(labels, "com.docker.security.userns=enabled")
	}
	if daemon.fipsEnabled {
		v.SecurityOptions = append(v.SecurityOptions, "name=fips")
		labels = append(labels, "com.docker.security.fips=enabled")
	}
	labels = append(labels, "com.docker.content-trust.mode="+string(trust.Mode(cfg.ContentTrust)))
	v.Labels = labels
}
