package authboss

import (
	"fmt"
	"net/http"
	"path"
)

// Handler augments http.HandlerFunc with a context.
type HandlerFunc func(*Context, http.ResponseWriter, *http.Request) error

// RouteTable is a routing table from a path to a handlerfunc.
type RouteTable map[string]HandlerFunc

// NewRouter returns a router to be mounted at some mountpoint.
func NewRouter() http.Handler {
	mux := http.NewServeMux()

	for name, mod := range modules {
		for route, handler := range mod.Routes() {
			fmt.Fprintf(Cfg.LogWriter, "%-10s Register Route: %s\n", "["+name+"]", route)
			mux.Handle(path.Join(Cfg.MountPath, route), contextRoute{handler})
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
		fmt.Fprintf(Cfg.LogWriter, "route: Malformed request, could not create context: %v", err)
		return
	}

	ctx.CookieStorer = Cfg.CookieStoreMaker(w, r)
	ctx.SessionStorer = Cfg.SessionStoreMaker(w, r)

	err = c.fn(ctx, w, r)
	if err == nil {
		return
	}

	fmt.Fprintf(Cfg.LogWriter, "Error Occurred at %s: %v", r.URL.Path, err)
	switch e := err.(type) {
	case AttributeErr:
		w.WriteHeader(http.StatusInternalServerError)
	case ClientDataErr:
		w.WriteHeader(http.StatusBadRequest)
	case ErrAndRedirect:
		if len(e.FlashSuccess) > 0 {
			ctx.CookieStorer.Put(FlashSuccessKey, e.FlashSuccess)
		}
		if len(e.FlashError) > 0 {
			ctx.CookieStorer.Put(FlashErrorKey, e.FlashError)
		}
		http.Redirect(w, r, e.Endpoint, http.StatusTemporaryRedirect)
	case RenderErr:
		w.WriteHeader(http.StatusInternalServerError)
	}
}
