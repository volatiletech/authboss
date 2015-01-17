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
func NewRouter() http.Handler {
	mux := http.NewServeMux()

	for name, mod := range modules {
		for route, handler := range mod.Routes() {
			fmt.Fprintf(cfg.LogWriter, "%-10s Register Route: %s\n", "["+name+"]", route)
			mux.Handle(path.Join(cfg.MountPath, route), contextRoute{handler})
		}
	}

	return mux
}

type contextRoute struct {
	fn HandlerFunc
}

func (c contextRoute) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, err := ContextFromRequest(r)
	if err != nil {
		fmt.Fprintf(cfg.LogWriter, "route: Malformed request, could not create context: %v", err)
		return
	}

	ctx.CookieStorer = cfg.CookieStoreMaker(w, r)
	ctx.SessionStorer = cfg.SessionStoreMaker(w, r)

	c.fn(ctx, w, r)
}
