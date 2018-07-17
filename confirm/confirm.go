// Package confirm implements confirmation of user registration via e-mail
package confirm

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"

	"github.com/volatiletech/authboss"
)

const (
	// PageConfirm is only really used for the BodyReader
	PageConfirm = "confirm"

	// EmailConfirmHTML is the name of the html template for e-mails
	EmailConfirmHTML = "confirm_html"
	// EmailConfirmTxt is the name of the text template for e-mails
	EmailConfirmTxt = "confirm_txt"

	// FormValueConfirm is the name of the form value for
	FormValueConfirm = "cnf"

	// DataConfirmURL is the name of the e-mail template variable
	// that gives the url to send to the user for confirmation.
	DataConfirmURL = "url"

	confirmTokenSize  = 64
	confirmTokenSplit = confirmTokenSize / 2
)

func init() {
	authboss.RegisterModule("confirm", &Confirm{})
}

// Confirm module
type Confirm struct {
	*authboss.Authboss
}

// Init module
func (c *Confirm) Init(ab *authboss.Authboss) (err error) {
	c.Authboss = ab

	if err = c.Authboss.Config.Core.MailRenderer.Load(EmailConfirmHTML, EmailConfirmTxt); err != nil {
		return err
	}

	c.Authboss.Config.Core.Router.Get("/confirm", c.Authboss.Config.Core.ErrorHandler.Wrap(c.Get))

	c.Events.Before(authboss.EventAuth, c.PreventAuth)
	c.Events.After(authboss.EventRegister, c.StartConfirmationWeb)

	return nil
}

// PreventAuth stops the EventAuth from succeeding when a user is not confirmed
// This relies on the fact that the context holds the user at this point in time
// loaded by the auth module (or something else).
func (c *Confirm) PreventAuth(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	logger := c.Authboss.RequestLogger(r)

	user, err := c.Authboss.CurrentUser(r)
	if err != nil {
		return false, err
	}

	cuser := authboss.MustBeConfirmable(user)
	if cuser.GetConfirmed() {
		logger.Infof("user %s was confirmed, allowing auth", user.GetPID())
		return false, nil
	}

	logger.Infof("user %s was not confirmed, preventing auth", user.GetPID())
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: c.Authboss.Config.Paths.ConfirmNotOK,
		Failure:      "Your account has not been confirmed, please check your e-mail.",
	}
	return true, c.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// StartConfirmationWeb hijacks a request and forces a user to be confirmed first
// it's assumed that the current user is loaded into the request context.
func (c *Confirm) StartConfirmationWeb(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	user, err := c.Authboss.CurrentUser(r)
	if err != nil {
		return false, err
	}

	cuser := authboss.MustBeConfirmable(user)
	if err = c.StartConfirmation(r.Context(), cuser, true); err != nil {
		return false, err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: c.Authboss.Config.Paths.ConfirmNotOK,
		Success:      "Please verify your account, an e-mail has been sent to you.",
	}
	return true, c.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// StartConfirmation begins confirmation on a user by setting them to require confirmation
// via a created token, and optionally sending them an e-mail.
func (c *Confirm) StartConfirmation(ctx context.Context, user authboss.ConfirmableUser, sendEmail bool) error {
	logger := c.Authboss.Logger(ctx)

	selector, verifier, token, err := GenerateConfirmCreds()
	if err != nil {
		return err
	}

	user.PutConfirmed(false)
	user.PutConfirmSelector(selector)
	user.PutConfirmVerifier(verifier)

	logger.Infof("generated new confirm token for user: %s", user.GetPID())
	if err := c.Authboss.Config.Storage.Server.Save(ctx, user); err != nil {
		return errors.Wrap(err, "failed to save user during StartConfirmation, user data may be in weird state")
	}

	goConfirmEmail(c, ctx, user.GetEmail(), token)

	return nil
}

// This is here so it can be mocked out by a test
var goConfirmEmail = func(c *Confirm, ctx context.Context, to, token string) {
	go c.SendConfirmEmail(ctx, to, token)
}

// SendConfirmEmail sends a confirmation e-mail to a user
func (c *Confirm) SendConfirmEmail(ctx context.Context, to, token string) {
	logger := c.Authboss.Logger(ctx)

	p := path.Join(c.Config.Paths.Mount, "confirm")
	url := fmt.Sprintf("%s%s?%s=%s", c.Paths.RootURL, p, url.QueryEscape(FormValueConfirm), url.QueryEscape(token))

	email := authboss.Email{
		To:       []string{to},
		From:     c.Config.Mail.From,
		FromName: c.Config.Mail.FromName,
		Subject:  c.Config.Mail.SubjectPrefix + "Confirm New Account",
	}

	logger.Infof("sending confirm e-mail to: %s", to)

	ro := authboss.EmailResponseOptions{
		Data:         authboss.NewHTMLData(DataConfirmURL, url),
		HTMLTemplate: EmailConfirmHTML,
		TextTemplate: EmailConfirmTxt,
	}
	if err := c.Authboss.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to send confirm e-mail to %s: %+v", to, err)
	}
}

// Get is a request that confirms a user with a valid token
func (c *Confirm) Get(w http.ResponseWriter, r *http.Request) error {
	logger := c.RequestLogger(r)

	validator, err := c.Authboss.Config.Core.BodyReader.Read(PageConfirm, r)
	if err != nil {
		return err
	}

	if errs := validator.Validate(); errs != nil {
		logger.Infof("validation failed in Confirm.Get, this typically means a bad token: %+v", errs)
		return c.invalidToken(w, r)
	}

	values := authboss.MustHaveConfirmValues(validator)

	rawToken, err := base64.URLEncoding.DecodeString(values.GetToken())
	if err != nil {
		logger.Infof("error decoding token in Confirm.Get, this typically means a bad token: %s %+v", values.GetToken(), err)
		return c.invalidToken(w, r)
	}

	if len(rawToken) != confirmTokenSize {
		logger.Infof("invalid confirm token submitted, size was wrong: %d", len(rawToken))
		return c.invalidToken(w, r)
	}

	selectorBytes := sha512.Sum512(rawToken[:confirmTokenSplit])
	verifierBytes := sha512.Sum512(rawToken[confirmTokenSplit:])
	selector := base64.StdEncoding.EncodeToString(selectorBytes[:])

	storer := authboss.EnsureCanConfirm(c.Authboss.Config.Storage.Server)
	user, err := storer.LoadByConfirmSelector(r.Context(), selector)
	if err == authboss.ErrUserNotFound {
		logger.Infof("confirm selector was not found in database: %s", selector)
		return c.invalidToken(w, r)
	} else if err != nil {
		return err
	}

	dbVerifierBytes, err := base64.StdEncoding.DecodeString(user.GetConfirmVerifier())
	if err != nil {
		logger.Infof("invalid confirm verifier stored in database: %s", user.GetConfirmVerifier())
		return c.invalidToken(w, r)
	}

	if subtle.ConstantTimeEq(int32(len(verifierBytes)), int32(len(dbVerifierBytes))) != 1 ||
		subtle.ConstantTimeCompare(verifierBytes[:], dbVerifierBytes) != 1 {
		logger.Info("stored confirm verifier does not match provided one")
		return c.invalidToken(w, r)
	}

	user.PutConfirmSelector("")
	user.PutConfirmVerifier("")
	user.PutConfirmed(true)

	logger.Infof("user %s confirmed their account", user.GetPID())
	if err = c.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Success:      "You have successfully confirmed your account.",
		RedirectPath: c.Authboss.Config.Paths.ConfirmOK,
	}
	return c.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

func (c *Confirm) invalidToken(w http.ResponseWriter, r *http.Request) error {
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Failure:      "confirm token is invalid",
		RedirectPath: c.Authboss.Config.Paths.ConfirmNotOK,
	}
	return c.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// Middleware ensures that a user is confirmed, or else it will intercept the request
// and send them to the confirm page, this will load the user if he's not been loaded
// yet from the session.
//
// Panics if the user was not able to be loaded in order to allow a panic handler to show
// a nice error page, also panics if it failed to redirect for whatever reason.
func Middleware(ab *authboss.Authboss) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := ab.LoadCurrentUserP(&r)

			cu := authboss.MustBeConfirmable(user)
			if cu.GetConfirmed() {
				next.ServeHTTP(w, r)
				return
			}

			logger := ab.RequestLogger(r)
			logger.Infof("user %s prevented from accessing %s: not confirmed", user.GetPID(), r.URL.Path)
			ro := authboss.RedirectOptions{
				Code:         http.StatusTemporaryRedirect,
				Failure:      "Your account has not been confirmed, please check your e-mail.",
				RedirectPath: ab.Config.Paths.ConfirmNotOK,
			}
			ab.Config.Core.Redirector.Redirect(w, r, ro)
		})
	}
}

// GenerateConfirmCreds generates pieces needed for user confirmy
// selector: hash of the first half of a 64 byte value (to be stored in the database and used in SELECT query)
// verifier: hash of the second half of a 64 byte value (to be stored in database but never used in SELECT query)
// token: the user-facing base64 encoded selector+verifier
func GenerateConfirmCreds() (selector, verifier, token string, err error) {
	rawToken := make([]byte, confirmTokenSize)
	if _, err = io.ReadFull(rand.Reader, rawToken); err != nil {
		return "", "", "", err
	}
	selectorBytes := sha512.Sum512(rawToken[:confirmTokenSplit])
	verifierBytes := sha512.Sum512(rawToken[confirmTokenSplit:])

	return base64.StdEncoding.EncodeToString(selectorBytes[:]),
		base64.StdEncoding.EncodeToString(verifierBytes[:]),
		base64.URLEncoding.EncodeToString(rawToken),
		nil
}
