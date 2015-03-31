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
func (a *Authboss) NewRouter() http.Handler {
	if a.mux != nil {
		return a.mux
	}
	a.mux = http.NewServeMux()

	for name, mod := range a.loadedModules {
		for route, handler := range mod.Routes() {
			fmt.Fprintf(a.LogWriter, "%-10s Route: %s\n", "["+name+"]", path.Join(a.MountPath, route))
			a.mux.Handle(path.Join(a.MountPath, route), contextRoute{a, handler})
		}
	}

	a.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if a.NotFoundHandler != nil {
			a.NotFoundHandler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "404 Page not found")
		}
	})

	return a.mux
}

type contextRoute struct {
	*Authboss
	fn HandlerFunc
}

func (c contextRoute) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, err := c.Authboss.ContextFromRequest(r)
	if err != nil {
		fmt.Fprintf(c.LogWriter, "route: Malformed request, could not create context: %v", err)
		return
	}

	ctx.CookieStorer = clientStoreWrapper{c.CookieStoreMaker(w, r)}
	ctx.SessionStorer = clientStoreWrapper{c.SessionStoreMaker(w, r)}

	err = c.fn(ctx, w, r)
	if err == nil {
		return
	}

	fmt.Fprintf(c.LogWriter, "Error Occurred at %s: %v", r.URL.Path, err)

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
		if c.BadRequestHandler != nil {
			c.BadRequestHandler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "400 Bad request")
		}
	default:
		if c.ErrorHandler != nil {
			c.ErrorHandler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "500 An error has occurred")
		}
	}
}
