package authboss

import (
	"fmt"
	"net/http"
	"path"
)

// Handler augments http.HandlerFunc with a context.
type HandlerFunc func(*Context, http.ResponseWriter, *http.Request)

// RouteTable is a routing table from a path to a handlerfunc.
type RouteTable map[string]HandlerFunc

// NewRouter returns a router to be mounted at some mountpoint.
func NewRouter(config *Config) http.Handler {
	mux := http.NewServeMux()

	for name, mod := range modules {
		for route, handler := range mod.Routes() {
			fmt.Fprintf(logger, "[%-10s] Register Route: %s\n", name, route)
			mux.Handle(path.Join(config.MountPath, route), contextRoute{handler})
		}
	}

	return mux
}

type contextRoute struct {
	fn HandlerFunc
}

func (c contextRoute) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext()

	c.fn(ctx, w, r)
}
