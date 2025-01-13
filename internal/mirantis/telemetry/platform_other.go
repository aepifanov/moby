//go:build !linux

package telemetry

import (
	"context"

	"github.com/segmentio/analytics-go/v3"
)

func fillPlatformTraits(context.Context, analytics.Traits) {}
