package authboss

import (
	"html/template"
	"net/http"

	"github.com/pkg/errors"
)

// Respond to an HTTP request. Renders templates, flash messages, does XSRF
// and writes the headers out.
func (a *Authboss) Respond(w http.ResponseWriter, r *http.Request, code int, templateName string, data HTMLData) error {
	data.MergeKV(
		"xsrfName", template.HTML(a.XSRFName),
		"xsrfToken", template.HTML(a.XSRFMaker(w, r)),
	)

	if a.LayoutDataMaker != nil {
		data.Merge(a.LayoutDataMaker(w, r))
	}

	flashSuccess := FlashSuccess(w, r)
	flashError := FlashError(w, r)
	if len(flashSuccess) != 0 {
		data.MergeKV(FlashSuccessKey, flashSuccess)
	}
	if len(flashError) != 0 {
		data.MergeKV(FlashErrorKey, flashError)
	}

	rendered, mime, err := a.renderer.Render(r.Context(), templateName, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", mime)
	w.WriteHeader(code)

	_, err = w.Write(rendered)
	return err
}

// EmailResponseOptions controls how e-mails are rendered and sent
type EmailResponseOptions struct {
	Data         HTMLData
	HTMLTemplate string
	TextTemplate string
}

// Email renders the e-mail templates and sends it using the mailer.
func (a *Authboss) Email(w http.ResponseWriter, r *http.Request, email Email, ro EmailResponseOptions) error {
	ctx := r.Context()

	if len(ro.HTMLTemplate) != 0 {
		htmlBody, _, err := a.renderer.Render(ctx, ro.HTMLTemplate, ro.Data)
		if err != nil {
			return errors.Wrap(err, "failed to render e-mail html body")
		}
		email.HTMLBody = string(htmlBody)
	}

	if len(ro.TextTemplate) != 0 {
		textBody, _, err := a.renderer.Render(ctx, ro.TextTemplate, ro.Data)
		if err != nil {
			return errors.Wrap(err, "failed to render e-mail text body")
		}
		email.TextBody = string(textBody)
	}

	return a.Mailer.Send(ctx, email)
}

// RedirectOptions packages up all the pieces a module needs to write out a
// response.
type RedirectOptions struct {
	// Success & Failure are used to set Flash messages / JSON messages
	// if set. They should be mutually exclusive.
	Success string
	Failure string

	// Code is used when it's an API request instead of 200.
	Code int

	// When a request should redirect a user somewhere on completion, these
	// should be set. RedirectURL tells it where to go. And optionally set
	// FollowRedirParam to override the RedirectURL if the form parameter defined
	// by FormValueRedirect is passed in the request.
	//
	// Redirecting works differently whether it's an API request or not.
	// If it's an API request, then it will leave the URL in a "redirect"
	// parameter.
	RedirectPath     string
	FollowRedirParam bool
}

// Redirect the client elsewhere. If it's an API request it will simply render
// a JSON response with information that should help a client to decide what
// to do.
func (a *Authboss) Redirect(w http.ResponseWriter, r *http.Request, ro RedirectOptions) error {
	var redirectFunction = a.redirectNonAPI
	if isAPIRequest(r) {
		redirectFunction = a.redirectAPI
	}

	return redirectFunction(w, r, ro)
}

func (a *Authboss) redirectAPI(w http.ResponseWriter, r *http.Request, ro RedirectOptions) error {
	path := ro.RedirectPath
	redir := r.FormValue(FormValueRedirect)
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

	data := HTMLData{
		"path": path,
	}

	if len(status) != 0 {
		data["status"] = status
		data["message"] = message
	}

	body, mime, err := a.renderer.Render(r.Context(), "redirect", data)
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

func (a *Authboss) redirectNonAPI(w http.ResponseWriter, r *http.Request, ro RedirectOptions) error {
	path := ro.RedirectPath
	redir := r.FormValue(FormValueRedirect)
	if len(redir) != 0 && ro.FollowRedirParam {
		path = redir
	}

	if len(ro.Success) != 0 {
		PutSession(w, FlashSuccessKey, ro.Success)
	}
	if len(ro.Failure) != 0 {
		PutSession(w, FlashErrorKey, ro.Failure)
	}

	http.Redirect(w, r, path, http.StatusFound)
	return nil
}
