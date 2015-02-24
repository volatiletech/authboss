// Package confirm implements user confirming after N bad sign-in attempts.
package confirm

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/render"
)

const (
	StoreConfirmToken = "confirm_token"
	StoreConfirmed    = "confirmed"

	FormValueConfirm = "cnf"

	tplConfirmHTML = "confirm_email.html.tpl"
	tplConfirmText = "confirm_email.txt.tpl"
)

var (
	errUserMissing = errors.New("confirm: After registration user must be loaded")
)

// ConfirmStorer must be implemented in order to satisfy the confirm module's
// storage requirements.
type ConfirmStorer interface {
	authboss.Storer
	// ConfirmUser looks up a user by a confirm token. See confirm module for
	// attribute names. If the token is not found in the data store,
	// simply return nil, ErrUserNotFound.
	ConfirmUser(confirmToken string) (interface{}, error)
}

// C is the singleton instance of the confirm module which will have been
// configured and ready to use after authboss.Init()
var C *Confirm

func init() {
	C = &Confirm{}
	authboss.RegisterModule("confirm", C)
}

type Confirm struct {
	emailTemplates render.Templates
}

func (c *Confirm) Initialize() (err error) {
	var ok bool
	storer, ok := authboss.Cfg.Storer.(ConfirmStorer)
	if storer == nil || !ok {
		return errors.New("confirm: Need a ConfirmStorer.")
	}

	c.emailTemplates, err = render.LoadTemplates(authboss.Cfg.LayoutEmail, authboss.Cfg.ViewsPath, tplConfirmHTML, tplConfirmText)
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

func (c *Confirm) BeforeGet(ctx *authboss.Context) (authboss.Interrupt, error) {
	if confirmed, err := ctx.User.BoolErr(StoreConfirmed); err != nil {
		return authboss.InterruptNone, err
	} else if !confirmed {
		return authboss.InterruptAccountNotConfirmed, nil
	}

	return authboss.InterruptNone, nil
}

// AfterRegister ensures the account is not activated.
func (c *Confirm) AfterRegister(ctx *authboss.Context) error {
	if ctx.User == nil {
		return errUserMissing
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	sum := md5.Sum(token)

	ctx.User[StoreConfirmToken] = base64.StdEncoding.EncodeToString(sum[:])

	if err := ctx.SaveUser(); err != nil {
		return err
	}

	email, err := ctx.User.StringErr(authboss.StoreEmail)
	if err != nil {
		return err
	}

	goConfirmEmail(c, email, base64.URLEncoding.EncodeToString(sum[:]))

	return nil
}

var goConfirmEmail = func(c *Confirm, to, token string) {
	go c.confirmEmail(to, token)
}

// confirmEmail sends a confirmation e-mail.
func (c *Confirm) confirmEmail(to, token string) {
	url := fmt.Sprintf("%s/confirm?%s=%s", authboss.Cfg.HostName, url.QueryEscape(FormValueConfirm), url.QueryEscape(token))

	email := authboss.Email{
		To:      []string{to},
		From:    authboss.Cfg.EmailFrom,
		Subject: authboss.Cfg.EmailSubjectPrefix + "Confirm New Account",
	}

	err := c.emailTemplates.RenderEmail(email, tplConfirmHTML, tplConfirmText, url)
	if err != nil {
		fmt.Fprintf(authboss.Cfg.LogWriter, "confirm: Failed to send e-mail: %v", err)
	}
}

func (c *Confirm) confirmHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	token, err := ctx.FirstFormValueErr(FormValueConfirm)
	if err != nil {
		return err
	}

	toHash, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return authboss.ErrAndRedirect{
			Location: "/", Err: fmt.Errorf("confirm: token failed to decode %q => %v\n", token, err),
		}
	}

	sum := md5.Sum(toHash)

	dbTok := base64.StdEncoding.EncodeToString(sum[:])
	user, err := authboss.Cfg.Storer.(ConfirmStorer).ConfirmUser(dbTok)
	if err == authboss.ErrUserNotFound {
		return authboss.ErrAndRedirect{Location: "/", Err: errors.New("confirm: token not found")}
	} else if err != nil {
		return err
	}

	ctx.User = authboss.Unbind(user)

	ctx.User[StoreConfirmToken] = ""
	ctx.User[StoreConfirmed] = true

	key, err := ctx.User.StringErr(authboss.StoreUsername)
	if err != nil {
		return err
	}

	if err := ctx.SaveUser(); err != nil {
		return err
	}

	ctx.SessionStorer.Put(authboss.SessionKey, key)
	render.Redirect(ctx, w, r, "/", "You have successfully confirmed your account.", "")

	return nil
}
