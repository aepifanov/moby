package telemetry

import (
	"context"
	"net/http"

	"github.com/docker/docker/api/server/router"
)

type Backend interface {
	Send(context.Context)
}

type telemetryRouter struct {
	backend Backend
	routes  []router.Route
}

func NewRouter(b Backend) router.Router {
	r := &telemetryRouter{
		backend: b,
	}

	r.routes = []router.Route{
		router.NewPostRoute("/internal/telemetry", r.postTelemetryTest),
	}

	return r
}

func (r *telemetryRouter) postTelemetryTest(ctx context.Context, w http.ResponseWriter, _ *http.Request, _ map[string]string) error {
	r.backend.Send(ctx)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (r *telemetryRouter) Routes() []router.Route {
	return r.routes
}
