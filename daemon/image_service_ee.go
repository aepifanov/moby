package daemon

import (
	"context"
	"io"

	"github.com/containerd/log"
	"github.com/distribution/reference"
	opts "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/daemon/trust"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type TrustedImageService struct {
	ImageService
	Daemon       *Daemon
	TrustService *trust.Service
}

var _ ImageService = (*TrustedImageService)(nil)

func (i *TrustedImageService) PullImage(ctx context.Context, ref reference.Named, platform *ocispec.Platform, metaHeaders map[string][]string, authConfig *registry.AuthConfig, outStream io.Writer) error {
	var (
		pullRef      = ref
		canonicalRef reference.Canonical
		err          error
	)

	cfg := i.Daemon.config().ContentTrust
	if trust.Mode(cfg) != config.TrustModeDisabled {
		canonicalRef, err = i.TrustService.VerifyImageSigned(ctx, cfg, ref, authConfig, metaHeaders)
		if err != nil {
			return err
		}
		// if there was no error, but no canonical ref was returned, then it is because we're in
		// permissive mode, so we should fallback to untrusted codepath.
		if canonicalRef != nil {
			pullRef = canonicalRef
		}
	}

	err = i.ImageService.PullImage(ctx, pullRef, platform, metaHeaders, authConfig, outStream)
	if err != nil {
		return err
	}

	// When the canonical reference is passed to distribution, it will pull by digest, but not
	// update the tag when the image has been pulled.  So it will be displayed as <none> for
	// the tag.  We want to try to make sure that if a tag was provided by the user originally
	// (or if no digest was provided, and hence the tag is "latest"), that the image ends up
	// tagged.
	if tag, ok := ref.(reference.Tagged); ok && canonicalRef != nil {
		// do best effort re-tagging of image after done
		img, err := i.ImageService.GetImage(ctx, canonicalRef.String(), opts.GetImageOpts{})
		if err != nil {
			log.G(ctx).WithError(err).Warnf("unable to get image %s for re-tagging as %s", reference.FamiliarString(canonicalRef), tag.Tag())
		}
		err = i.TagImage(ctx, img.ID(), ref)
		if err != nil {
			log.G(ctx).WithError(err).Warnf("unable to re-tag %s as %s", reference.FamiliarString(canonicalRef), tag.Tag())
		}
	}
	return nil
}
