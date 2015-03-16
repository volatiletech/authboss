package authboss

import (
	"fmt"
	"io"
	"net/http"
	"path"
)

// HandlerFunc augments http.HandlerFunc with a context and error handling.
type HandlerFunc func(*Context, http.ResponseWriter, *http.Request) error

// RouteTable is a routing table from a path to a handlerfunc.
type RouteTable map[string]HandlerFunc

// NewRouter returns a router to be mounted at some mountpoint.
func NewRouter() http.Handler {
	mux := http.NewServeMux()

	for name, mod := range modules {
		for route, handler := range mod.Routes() {
			fmt.Fprintf(Cfg.LogWriter, "%-10s Register Route: %s\n", "["+name+"]", path.Join(Cfg.MountPath, route))
			mux.Handle(path.Join(Cfg.MountPath, route), contextRoute{handler})
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if Cfg.NotFoundHandler != nil {
			Cfg.NotFoundHandler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "404 Page not found")
		}
	})

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

	ctx.CookieStorer = clientStoreWrapper{Cfg.CookieStoreMaker(w, r)}
	ctx.SessionStorer = clientStoreWrapper{Cfg.SessionStoreMaker(w, r)}

	err = c.fn(ctx, w, r)
	if err == nil {
		return
	}

	fmt.Fprintf(Cfg.LogWriter, "Error Occurred at %s: %v", r.URL.Path, err)

	switch e := err.(type) {
	case ErrAndRedirect:
		if len(e.FlashSuccess) > 0 {
			ctx.SessionStorer.Put(FlashSuccessKey, e.FlashSuccess)
		}
		if len(e.FlashError) > 0 {
			ctx.SessionStorer.Put(FlashErrorKey, e.FlashError)
		}
		http.Redirect(w, r, e.Location, http.StatusFound)
	case ClientDataErr:
		if Cfg.BadRequestHandler != nil {
			Cfg.BadRequestHandler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "400 Bad request")
		}
	default:
		if Cfg.ErrorHandler != nil {
			Cfg.ErrorHandler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "500 An error has occurred")
		}
	}
}
