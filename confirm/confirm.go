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
	"net/url"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/views"
)

const (
	UserConfirmToken = "confirm_token"
	UserConfirmed    = "confirmed"
	UserEmail        = "email"

	FormValueConfirm = "cnf"

	tplConfirmHTML = "confirm_email.html.tpl"
	tplConfirmText = "confirm_email.txt.tpl"
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
	storer authboss.ConfirmStorer

	config         *authboss.Config
	emailTemplates views.Templates
}

func (c *Confirm) Initialize(config *authboss.Config) (err error) {
	var ok bool
	c.storer, ok = config.Storer.(authboss.ConfirmStorer)
	if config.Storer == nil || !ok {
		return errors.New("confirm: Need a ConfirmStorer.")
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
		if confirmed, ok := intf.(bool); !ok && !confirmed {
			return ErrNotConfirmed
		}
	}

	return nil
}

// AfterRegister ensures the account is not activated.
func (c *Confirm) AfterRegister(ctx *authboss.Context) {
	if ctx.User == nil {
		fmt.Fprintln(c.logger, "confirm: user not loaded in AfterRegister callback")
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to produce random token:", err)
	}
	sum := md5.Sum(token)

	ctx.User[UserConfirmToken] = base64.StdEncoding.EncodeToString(sum[:])

	username, _ := ctx.User.String(authboss.UserName)

	if err := ctx.SaveUser(username, c.config.Storer); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to save user's token:", err)
		return
	}

	if email, ok := ctx.User.String(UserEmail); !ok {
		fmt.Fprintln(c.logger, "confirm: user has no e-mail address to send to, could not send confirm e-mail")
	} else {
		goConfirmEmail(c, email, base64.URLEncoding.EncodeToString(sum[:]))
	}
}

var goConfirmEmail = func(c *Confirm, to, token string) {
	go c.confirmEmail(to, token)
}

// confirmEmail sends a confirmation e-mail.
func (c *Confirm) confirmEmail(to, token string) {
	url := fmt.Sprintf("%s/confirm?%s=%s", c.config.HostName, url.QueryEscape(FormValueConfirm), url.QueryEscape(token))

	var htmlEmailBody, textEmailBody *bytes.Buffer
	var err error
	if htmlEmailBody, err = c.emailTemplates.ExecuteTemplate(tplConfirmHTML, url); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to build html template:", err)
		return
	}

	if textEmailBody, err = c.emailTemplates.ExecuteTemplate(tplConfirmText, url); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to build plaintext template:", err)
		return
	}

	if err := c.config.Mailer.Send(authboss.Email{
		To:       []string{to},
		From:     c.config.EmailFrom,
		Subject:  c.config.EmailSubjectPrefix + "Confirm New Account",
		TextBody: textEmailBody.String(),
		HTMLBody: htmlEmailBody.String(),
	}); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to build plaintext template:", err)
	}
}

func (c *Confirm) confirmHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	token, ok := ctx.FirstFormValue(FormValueConfirm)
	if len(token) == 0 || !ok {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		fmt.Fprintln(c.logger, "confirm: no confirm token found in get")
		return
	}

	tok, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		fmt.Fprintf(c.logger, "confirm: confirm token failed to decode %q => %v\n", token, err)
		return
	}

	dbTok := base64.StdEncoding.EncodeToString(tok)
	user, err := c.storer.ConfirmUser(dbTok)
	if err == authboss.ErrUserNotFound {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		fmt.Fprintln(c.logger, "confirm: token not found", err)
		return
	} else if err != nil {
		w.WriteHeader(500)
		fmt.Fprintln(c.logger, "confirm: error retrieving user token:", err)
		return
	}

	ctx.User = authboss.Unbind(user)

	ctx.User[UserConfirmToken] = ""
	ctx.User[UserConfirmed] = true

	key, ok := ctx.User.String(authboss.UserName)
	if !ok {
		w.WriteHeader(500)
		fmt.Fprintln(c.logger, "confirm: user had no key field")
		return
	}

	ctx.SessionStorer.Put(authboss.SessionKey, key)
	ctx.SessionStorer.Put(authboss.FlashSuccessKey, "Successfully confirmed your account.")

	if err := ctx.SaveUser(key, c.config.Storer); err != nil {
		fmt.Fprintln(c.logger, "confirm: failed to clear the user's token:", err)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
