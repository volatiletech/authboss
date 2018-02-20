package defaults

import (
	"net/http"

	"github.com/volatiletech/authboss"
)

const (
	// RedirectFormValueName is the name of the form field
	// in the http request that will be used when redirecting
	RedirectFormValueName = "redir"
)

// Responder helps respond to http requests
type Responder struct {
	Renderer authboss.Renderer
}

// NewResponder constructor
func NewResponder(renderer authboss.Renderer) *Responder {
	return &Responder{Renderer: renderer}
}

// Respond to an HTTP request. It's main job is to merge data that comes in from
// various middlewares via the context with the data sent by the controller and render that.
func (r *Responder) Respond(w http.ResponseWriter, req *http.Request, code int, page string, data authboss.HTMLData) error {
	ctxData := req.Context().Value(authboss.CTXKeyData)
	if ctxData != nil {
		data.Merge(ctxData.(authboss.HTMLData))
	}

	rendered, mime, err := r.Renderer.Render(req.Context(), page, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", mime)
	w.WriteHeader(code)

	_, err = w.Write(rendered)
	return err
}

func isAPIRequest(r *http.Request) bool {
	return r.Header.Get("Content-Type") == "application/json"
}

// Redirector for http requests
type Redirector struct {
	Renderer authboss.Renderer

	// FormValueName for the redirection
	FormValueName string
}

// NewRedirector constructor
func NewRedirector(renderer authboss.Renderer, formValueName string) *Redirector {
	return &Redirector{FormValueName: formValueName, Renderer: renderer}
}

// Redirect the client elsewhere. If it's an API request it will simply render
// a JSON response with information that should help a client to decide what
// to do.
func (r *Redirector) Redirect(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	var redirectFunction = r.redirectNonAPI
	if isAPIRequest(req) {
		redirectFunction = r.redirectAPI
	}

	return redirectFunction(w, req, ro)
}

func (r Redirector) redirectAPI(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	path := ro.RedirectPath
	redir := req.FormValue(r.FormValueName)
	if len(redir) != 0 && ro.FollowRedirParam {
		path = redir
	}

	var status, message string
	if len(ro.Success) != 0 {
		status = "success"
		message = ro.Success
	}
	if len(ro.Failure) != 0 {
		status = "failure"
		message = ro.Failure
	}

	data := authboss.HTMLData{
		"location": path,
	}

	if len(status) != 0 {
		data["status"] = status
		data["message"] = message
	}

	body, mime, err := r.Renderer.Render(req.Context(), "redirect", data)
	if err != nil {
		return err
	}

	if len(body) != 0 {
		w.Header().Set("Content-Type", mime)
	}

	if ro.Code != 0 {
		w.WriteHeader(ro.Code)
	}
	_, err = w.Write(body)
	return err
}

func (r Redirector) redirectNonAPI(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	path := ro.RedirectPath
	redir := req.FormValue(r.FormValueName)
	if len(redir) != 0 && ro.FollowRedirParam {
		path = redir
	}

	if len(ro.Success) != 0 {
		authboss.PutSession(w, authboss.FlashSuccessKey, ro.Success)
	}
	if len(ro.Failure) != 0 {
		authboss.PutSession(w, authboss.FlashErrorKey, ro.Failure)
	}

	http.Redirect(w, req, path, http.StatusFound)
	return nil
}
