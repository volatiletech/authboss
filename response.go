package authboss

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
)

// HTTPResponder knows how to respond to an HTTP request
// Must consider:
// - Flash messages
// - XSRF handling (template data)
// - Assembling template data from various sources
//
// Authboss controller methods (like the one called in response to POST /auth/login)
// will call this method to write a response to the user.
type HTTPResponder interface {
	Respond(w http.ResponseWriter, r *http.Request, code int, templateName string, data HTMLData) error
}

// HTTPRedirector redirects http requests to a different url (must handle both json and html)
// When an authboss controller wants to redirect a user to a different path, it will use
// this interface.
type HTTPRedirector interface {
	Redirect(w http.ResponseWriter, r *http.Request, ro RedirectOptions) error
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

// EmailResponseOptions controls how e-mails are rendered and sent
type EmailResponseOptions struct {
	Data         HTMLData
	HTMLTemplate string
	TextTemplate string
}

// Email renders the e-mail templates and sends it using the mailer.
func (a *Authboss) Email(ctx context.Context, email Email, ro EmailResponseOptions) error {
	if len(ro.HTMLTemplate) != 0 {
		htmlBody, _, err := a.Core.MailRenderer.Render(ctx, ro.HTMLTemplate, ro.Data)
		if err != nil {
			return errors.Wrap(err, "failed to render e-mail html body")
		}
		email.HTMLBody = string(htmlBody)
	}

	if len(ro.TextTemplate) != 0 {
		textBody, _, err := a.Core.MailRenderer.Render(ctx, ro.TextTemplate, ro.Data)
		if err != nil {
			return errors.Wrap(err, "failed to render e-mail text body")
		}
		email.TextBody = string(textBody)
	}

	return a.Core.Mailer.Send(ctx, email)
}
