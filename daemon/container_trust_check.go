package daemon // import "github.com/docker/docker/daemon"

import (
	"context"

	"github.com/distribution/reference"
	imagetype "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/daemon/trust"
	"github.com/docker/docker/errdefs"
	"github.com/pkg/errors"
)

// The image reference inside a container config or a container object may just
// be an ID.  We have to look it up in the image service to see what image it
// maps to, first
func (daemon *Daemon) verifyImageSigned(ctx context.Context, cfg *configStore, image string) error {
	if trust.Mode(cfg.ContentTrust) == config.TrustModeDisabled {
		return nil
	}
	inspectInfo, err := daemon.imageService.GetImage(ctx, image, imagetype.GetImageOpts{Details: true})
	if err != nil {
		return err
	}

	// do any of the digests validate?
	for _, ref := range inspectInfo.Details.References {
		digested, ok := ref.(reference.Canonical)
		if !ok {
			continue
		}

		if _, err := daemon.trustService.VerifyImageSigned(ctx, cfg.ContentTrust, digested, nil, nil); err == nil {
			return nil // yay, at least one signed
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return errdefs.Forbidden(
		errors.Errorf("could not find trust signature for local image %s", image))
}
