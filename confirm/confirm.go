// Package confirm implements user confirming after N bad sign-in attempts.
package confirm

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/views"
)

const (
	StoreConfirmToken = "confirm_token"
	StoreConfirmed    = "confirmed"

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
	emailTemplates views.Templates
}

func (c *Confirm) Initialize() (err error) {
	var ok bool
	storer, ok := authboss.Cfg.Storer.(authboss.ConfirmStorer)
	if storer == nil || !ok {
		return errors.New("confirm: Need a ConfirmStorer.")
	}

	c.emailTemplates, err = views.Get(authboss.Cfg.LayoutEmail, authboss.Cfg.ViewsPath, tplConfirmHTML, tplConfirmText)
	if err != nil {
		return err
	}

	authboss.Cfg.Callbacks.Before(authboss.EventGet, c.BeforeGet)
	authboss.Cfg.Callbacks.After(authboss.EventRegister, c.AfterRegister)

	return nil
}

func (c *Confirm) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/confirm": c.confirmHandler,
	}
}

func (c *Confirm) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		StoreConfirmToken: authboss.String,
		StoreConfirmed:    authboss.Bool,
	}
}

func (c *Confirm) BeforeGet(ctx *authboss.Context) error {
	if intf, ok := ctx.User[StoreConfirmed]; ok {
		if confirmed, ok := intf.(bool); ok && confirmed {
			return nil
		}
	}

	return ErrNotConfirmed
}

// AfterRegister ensures the account is not activated.
func (c *Confirm) AfterRegister(ctx *authboss.Context) {
	if ctx.User == nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: user not loaded in AfterRegister callback")
		return
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: failed to produce random token:", err)
	}
	sum := md5.Sum(token)

	ctx.User[StoreConfirmToken] = base64.StdEncoding.EncodeToString(sum[:])

	if err := ctx.SaveUser(); err != nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: failed to save user's token:", err)
		return
	}

	if email, ok := ctx.User.String(authboss.StoreEmail); !ok {
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: user has no e-mail address to send to, could not send confirm e-mail")
	} else {
		goConfirmEmail(c, email, base64.URLEncoding.EncodeToString(sum[:]))
	}
}

var goConfirmEmail = func(c *Confirm, to, token string) {
	go c.confirmEmail(to, token)
}

// confirmEmail sends a confirmation e-mail.
func (c *Confirm) confirmEmail(to, token string) {
	url := fmt.Sprintf("%s/confirm?%s=%s", authboss.Cfg.HostName, url.QueryEscape(FormValueConfirm), url.QueryEscape(token))

	var htmlEmailBody, textEmailBody *bytes.Buffer
	var err error
	if htmlEmailBody, err = c.emailTemplates.ExecuteTemplate(tplConfirmHTML, url); err != nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: failed to build html template:", err)
		return
	}

	if textEmailBody, err = c.emailTemplates.ExecuteTemplate(tplConfirmText, url); err != nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: failed to build plaintext template:", err)
		return
	}

	if err := authboss.Cfg.Mailer.Send(authboss.Email{
		To:       []string{to},
		From:     authboss.Cfg.EmailFrom,
		Subject:  authboss.Cfg.EmailSubjectPrefix + "Confirm New Account",
		TextBody: textEmailBody.String(),
		HTMLBody: htmlEmailBody.String(),
	}); err != nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: failed to build plaintext template:", err)
	}
}

func (c *Confirm) confirmHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	token, ok := ctx.FirstFormValue(FormValueConfirm)
	if len(token) == 0 || !ok {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: no confirm token found in request")
		return
	}

	toHash, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		fmt.Fprintf(authboss.Cfg.LogWriter, "confirm: confirm token failed to decode %q => %v\n", token, err)
		return
	}

	sum := md5.Sum(toHash)

	dbTok := base64.StdEncoding.EncodeToString(sum[:])
	user, err := authboss.Cfg.Storer.(authboss.ConfirmStorer).ConfirmUser(dbTok)
	if err == authboss.ErrUserNotFound {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: token not found:", err)
		return
	} else if err != nil {
		w.WriteHeader(500)
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: error retrieving user token:", err)
		return
	}

	ctx.User = authboss.Unbind(user)

	ctx.User[StoreConfirmToken] = ""
	ctx.User[StoreConfirmed] = true

	key, _ := ctx.User.String(authboss.StoreUsername)
	ctx.SessionStorer.Put(authboss.SessionKey, key)
	ctx.SessionStorer.Put(authboss.FlashSuccessKey, "Successfully confirmed your account.")

	if err := ctx.SaveUser(); err != nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "confirm: failed to clear the user's token:", err)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
