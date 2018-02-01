package defaults

import (
	"net/http"

	"github.com/volatiletech/authboss"
)

// Responder helps respond to http requests
type Responder struct {
	// CRSFHandler creates csrf tokens for inclusion on rendered forms
	CSRFMaker CSRFMaker
	// CRSFName is the name of the field that will include the token
	CSRFName string

	Renderer authboss.Renderer
}

// CSRFMaker returns an opaque string when handed a request and response
// to be included in the data as a
type CSRFMaker func(w http.ResponseWriter, r *http.Request) string

// Respond to an HTTP request. Renders templates, flash messages, does CSRF
// and writes the headers out.
func (r *Responder) Respond(w http.ResponseWriter, req *http.Request, code int, templateName string, data authboss.HTMLData) error {
	data.MergeKV(
		r.CSRFName, r.CSRFMaker(w, req),
	)

	/*
		TODO(aarondl): Add middlewares for accumulating eventual view data using contexts
		if a.LayoutDataMaker != nil {
			data.Merge(a.LayoutDataMaker(w, req))
		}

		flashSuccess := authboss.FlashSuccess(w, req)
		flashError := authboss.FlashError(w, req)
		if len(flashSuccess) != 0 {
			data.MergeKV(authboss.FlashSuccessKey, flashSuccess)
		}
		if len(flashError) != 0 {
			data.MergeKV(authboss.FlashErrorKey, flashError)
		}
	*/

	rendered, mime, err := r.Renderer.Render(req.Context(), templateName, data)
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
	// FormValueName for the redirection
	FormValueName string

	Renderer authboss.Renderer
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
