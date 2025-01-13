package daemon // import "github.com/docker/docker/daemon"

import (
	"context"
	"fmt"

	"github.com/containerd/log"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/container"
)

// ContainerUnpause unpauses a container
func (daemon *Daemon) ContainerUnpause(ctx context.Context, name string) error {
	ctr, err := daemon.GetContainer(name)
	if err != nil {
		return err
	}

	// Verify signature if trust service is not nil or disabled
	// There is no TrustedContainerUnpause method as there is for ContainerStart
	// because the only thing that calls ContainerUnpause is the API, where we want
	// the trust check to happen.
	if err := daemon.verifyImageSigned(ctx, daemon.config(), ctr.ImageID.String()); err != nil {
		return err
	}

	return daemon.containerUnpause(ctr)
}

// containerUnpause resumes the container execution after the container is paused.
func (daemon *Daemon) containerUnpause(ctr *container.Container) error {
	ctr.Lock()
	defer ctr.Unlock()

	// We cannot unpause the container which is not paused
	if !ctr.Paused {
		return fmt.Errorf("Container %s is not paused", ctr.ID)
	}
	tsk, err := ctr.GetRunningTask()
	if err != nil {
		return err
	}

	if err := tsk.Resume(context.Background()); err != nil {
		return fmt.Errorf("Cannot unpause container %s: %s", ctr.ID, err)
	}

	ctr.Paused = false
	daemon.setStateCounter(ctr)
	daemon.updateHealthMonitor(ctr)
	daemon.LogContainerEvent(ctr, events.ActionUnPause)

	if err := ctr.CheckpointTo(daemon.containersReplica); err != nil {
		log.G(context.TODO()).WithError(err).Warn("could not save container to disk")
	}

	return nil
}
