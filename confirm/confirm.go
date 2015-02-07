// Package confirm implements user confirming after N bad sign-in attempts.
package confirm

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/views"
)

const (
	UserConfirmToken = "confirm_token"
	UserConfirmed    = "confirmed"

	FormValueConfirm = "cnf"

	tplConfirmHTML = "confirm_email.html.tpl"
	tplConfirmText = "confirm_email.text.tpl"
)

var (
	// ErrNotConfirmed happens when the account is there, but
	// not yet confirmed.
	ErrNotConfirmed = errors.New("Account is not confirmed.")
)

// C is the singleton instance of the confirm module which will have been
// configured and ready to use after authboss.Init()
var C *Confirm

func init() {
	C = &Confirm{}
	authboss.RegisterModule("confirm", C)
}

type Confirm struct {
	logger io.Writer

	config         *authboss.Config
	emailTemplates views.Templates
}

func (c *Confirm) Initialize(config *authboss.Config) (err error) {
	if config.Storer == nil {
		return errors.New("confirm: Need a Storer.")
	}

	c.logger = config.LogWriter
	c.config = config

	c.emailTemplates, err = views.Get(config.LayoutEmail, config.ViewsPath, tplConfirmHTML, tplConfirmText)
	if err != nil {
		return err
	}

	config.Callbacks.Before(authboss.EventGet, c.BeforeGet)
	config.Callbacks.After(authboss.EventRegister, c.AfterRegister)

	return nil
}

func (c *Confirm) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/confirm": c.confirmHandler,
	}
}

func (c *Confirm) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		UserConfirmToken: authboss.String,
		UserConfirmed:    authboss.Bool,
	}
}

func (c *Confirm) BeforeGet(ctx *authboss.Context) error {
	if intf, ok := ctx.User[UserConfirmed]; ok {
		if confirmed, ok := intf.(bool); ok && confirmed {
			return ErrNotConfirmed
		}
	}
}

// AfterRegister ensures the account is not activated.
func (c *Confirm) AfterRegister(ctx *authboss.Context) {
	if ctx.User == nil {
		fmt.Fprintln(c.logger, "confirm: user not loaded in after register callback")
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to produce random token:", err)
	}
	sum := md5.Sum(token)

	ctx.User[UserConfirmToken] = base64.StdEncoding.EncodeToString(sum[:])

	if err := ctx.SaveUser(username, c.config.Storer); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to save user:", err)
	}

	if email, ok := ctx.User.String("email"); !ok {
		fmt.Fprintln(c.logger, "confirm: user has no e-mail address to send to, could not send confirm e-mail")
	} else {
		go c.confirmEmail(email, base64.URLEncoding.EncodeToString(sum[:]))
	}
}

// confirmEmail sends a confirmation e-mail.
func (c *Confirm) confirmEmail(to, token string) {
	url := fmt.Sprintf("%s/recover/complete?token=%s", c.config.HostName, token)

	htmlEmailBody := &bytes.Buffer{}
	if err := c.emailTemplates.ExecuteTemplate(htmlEmailBody, tplConfirmHTML, url); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to build html template:", err)
	}

	textEmailBody := &bytes.Buffer{}
	if err := c.emailTemplates.ExecuteTemplate(textEmailBody, tplConfirmText, url); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to build plaintext template:", err)
	}

	if err := m.config.Mailer.Send(authboss.Email{
		To:       []string{to},
		From:     c.config.EmailFrom,
		Subject:  c.config.EmailSubjectPrefix + "Confirm New Account",
		TextBody: textEmailBody.String(),
		HTMLBody: htmlEmailBody.String(),
	}); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to build plaintext template:", err)
	}
}

func (c *Confirm) confirmHandler(w http.ResponseWriter, r *http.Request) {
	ctx := authboss.ContextFromRequest(r)

	u, err := ctx.LoadUser(authboss.SessionKey, c.config.Storer)
	if err != nil {
		// 500
	}

	ctx.FirstFormValue(FormValueConfirm)

	token, ok := ctx.User.String(UserConfirmToken)
	if !ok {
		// Redirect no error
	}

	tok, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		// Redirect no error
	}

	dbTok := base64.StdEncoding.EncodeToString(tok)

	// Redirect to / with flash message.
	// Log user in.
	// Overwrite dbTok with empty string.
}
