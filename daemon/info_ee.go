package daemon

import (
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/opencontainers/selinux/go-selinux"
)

// fillSecurityLabels adds Docker EE specific labels and options to info
func (daemon *Daemon) fillSecurityLabels(v *system.Info, sysInfo *sysinfo.SysInfo) {
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
	v.Labels = labels
}
