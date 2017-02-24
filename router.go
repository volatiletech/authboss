package authboss

import (
	"fmt"
	"io"
	"net/http"
	"path"
)

// FormValue constants
const (
	FormValueRedirect = "redir"
)

// HandlerFunc augments http.HandlerFunc with a context and error handling.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

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
			a.mux.Handle(path.Join(a.MountPath, route), abHandler{a, handler})
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

type abHandler struct {
	*Authboss
	fn HandlerFunc
}

// TODO(aarondl): Move this somewhere reasonable
func isAPIRequest(r *http.Request) bool {
	return r.Header.Get("Content-Type") == "application/json"
}

func (a abHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Put uid in the context
	_, err := a.LoadCurrentUserID(w, &r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "500 An error has occurred")
		fmt.Fprintf(a.LogWriter, "failed to load current user id: %v", err)
		return
	}

	// Call the handler
	err = a.fn(w, r)
	if err == nil {
		return
	}

	// Log the error
	fmt.Fprintf(a.LogWriter, "Error Occurred at %s: %v", r.URL.Path, err)

	// Do specific error handling for special kinds of errors.
	if _, ok := err.(ClientDataErr); ok {
		if a.BadRequestHandler != nil {
			a.BadRequestHandler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "400 Bad request")
		}
		return
	}

	if a.ErrorHandler != nil {
		a.ErrorHandler.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "500 An error has occurred")
	}
}

/*
// TODO(aarondl): Throw away this function
// redirectIfLoggedIn checks a user's existence by using currentUser. This is done instead of
// a simple Session cookie check so that the remember module has a chance to log the user in
// before they are determined to "not be logged in".
//
// The exceptional routes are sort of hardcoded in a terrible way in here, later on this could move to some
// configuration or something more interesting.
func redirectIfLoggedIn(w http.ResponseWriter, r *http.Request) (handled bool) {
	// If it's a log out url, always let it pass through.
	if strings.HasSuffix(r.URL.Path, "/logout") {
		return false
	}

	// If it's an auth url, allow them through if they're half-authed.
	if strings.HasSuffix(r.URL.Path, "/auth") || strings.Contains(r.URL.Path, "/oauth2/") {
		if halfAuthed, ok := ctx.SessionStorer.Get(SessionHalfAuthKey); ok && halfAuthed == "true" {
			return false
		}
	}

	// Otherwise, check if they're logged in, this uses hooks to allow remember
	// to set the session cookie
	cu, err := ctx.currentUser(ctx, w, r)

	// if the user was not found, that means the user was deleted from the underlying
	// storer and we should just remove this session cookie and allow them through.
	// if it's a generic error, 500
	// if the user is found, redirect them away from this page, because they don't need
	// to see it.
	if err == ErrUserNotFound {
		uname, _ := ctx.SessionStorer.Get(SessionKey)
		fmt.Fprintf(ctx.LogWriter, "user (%s) has session cookie but user not found, removing cookie", uname)
		ctx.SessionStorer.Del(SessionKey)
		return false
	} else if err != nil {
		fmt.Fprintf(ctx.LogWriter, "error occurred reading current user at %s: %v", r.URL.Path, err)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "500 An error has occurred")
		return true
	}

	if cu != nil {
		if redir := r.FormValue(FormValueRedirect); len(redir) > 0 {
			http.Redirect(w, r, redir, http.StatusFound)
		} else {
			http.Redirect(w, r, ctx.AuthLoginOKPath, http.StatusFound)
		}
		return true
	}

	return false
}
*/
