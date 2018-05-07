// Package recover implements password reset via e-mail.
package recover

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/volatiletech/authboss"
)

// Constants for templates etc.
const (
	DataRecoverToken = "recover_token"
	DataRecoverURL   = "recover_url"

	FormValueToken = "token"

	EmailRecoverHTML = "recover_html"
	EmailRecoverTxt  = "recover_txt"

	PageRecoverStart  = "recover_start"
	PageRecoverMiddle = "recover_middle"
	PageRecoverEnd    = "recover_end"

	recoverInitiateSuccessFlash = "An email has been sent to you with further instructions on how to reset your password."
	recoverTokenExpiredFlash    = "Account recovery request has expired. Please try again."
	recoverFailedErrorFlash     = "Account recovery has failed. Please contact tech support."
)

func init() {
	m := &Recover{}
	authboss.RegisterModule("recover", m)
}

// Recover module
type Recover struct {
	*authboss.Authboss
}

// Init module
func (r *Recover) Init(ab *authboss.Authboss) (err error) {
	r.Authboss = ab

	if err := r.Authboss.Config.Core.ViewRenderer.Load(PageRecoverStart, PageRecoverEnd); err != nil {
		return err
	}

	if err := r.Authboss.Config.Core.MailRenderer.Load(EmailRecoverHTML, EmailRecoverTxt); err != nil {
		return err
	}

	r.Authboss.Config.Core.Router.Get("/recover", r.Core.ErrorHandler.Wrap(r.StartGet))
	r.Authboss.Config.Core.Router.Post("/recover", r.Core.ErrorHandler.Wrap(r.StartPost))
	r.Authboss.Config.Core.Router.Get("/recover/end", r.Core.ErrorHandler.Wrap(r.EndGet))
	r.Authboss.Config.Core.Router.Post("/recover/end", r.Core.ErrorHandler.Wrap(r.EndPost))

	return nil
}

// StartGet starts the recover procedure by rendering a form for the user.
func (r *Recover) StartGet(w http.ResponseWriter, req *http.Request) error {
	return r.Authboss.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverStart, nil)
}

// StartPost starts the recover procedure using values provided from the user
// usually from the StartGet's form.
func (r *Recover) StartPost(w http.ResponseWriter, req *http.Request) error {
	logger := r.RequestLogger(req)

	validatable, err := r.Authboss.Core.BodyReader.Read(PageRecoverStart, req)
	if err != nil {
		return err
	}

	recoverVals := authboss.MustHaveRecoverStartValues(validatable)

	user, err := r.Authboss.Storage.Server.Load(req.Context(), recoverVals.GetPID())
	if err == authboss.ErrUserNotFound {
		logger.Infof("user %s was attempted to be recovered, user does not exist, faking successful response", recoverVals.GetPID())
		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			RedirectPath: r.Authboss.Config.Paths.RecoverOK,
			Success:      recoverInitiateSuccessFlash,
		}
		return r.Authboss.Core.Redirector.Redirect(w, req, ro)
	}

	ru := authboss.MustBeRecoverable(user)

	hash, token, err := GenerateToken()
	if err != nil {
		return err
	}

	ru.PutRecoverToken(hash)
	ru.PutRecoverExpiry(time.Now().UTC().Add(r.Config.Modules.RecoverTokenDuration))

	if err := r.Authboss.Storage.Server.Save(req.Context(), ru); err != nil {
		return err
	}

	goRecoverEmail(r, req.Context(), ru.GetEmail(), token)

	logger.Infof("user %s password recovery initiated", ru.GetPID())
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: r.Authboss.Config.Paths.RecoverOK,
		Success:      recoverInitiateSuccessFlash,
	}
	return r.Authboss.Core.Redirector.Redirect(w, req, ro)
}

var goRecoverEmail = func(r *Recover, ctx context.Context, to, encodedToken string) {
	r.SendRecoverEmail(ctx, to, encodedToken)
}

// SendRecoverEmail to a specific e-mail address passing along the encodedToken
// in an escaped URL to the templates.
func (r *Recover) SendRecoverEmail(ctx context.Context, to, encodedToken string) {
	logger := r.Authboss.Logger(ctx)
	p := path.Join(r.Authboss.Config.Paths.Mount, "recover/end")
	query := url.Values{FormValueToken: []string{encodedToken}}
	url := fmt.Sprintf("%s%s?%s", r.Authboss.Config.Paths.RootURL, p, query.Encode())

	email := authboss.Email{
		To:      []string{to},
		From:    r.Authboss.Config.Mail.From,
		Subject: r.Authboss.Config.Mail.SubjectPrefix + "Password Reset",
	}

	ro := authboss.EmailResponseOptions{
		HTMLTemplate: EmailRecoverHTML,
		TextTemplate: EmailRecoverTxt,
		Data: authboss.HTMLData{
			DataRecoverURL: url,
		},
	}

	logger.Infof("sending recover e-mail to: %s", to)
	if err := r.Authboss.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to recover send e-mail to %s: %+v", to, err)
	}
}

// EndGet shows a password recovery form, and it should have the token that the user
// brought in the query parameters in it on submission.
func (r *Recover) EndGet(w http.ResponseWriter, req *http.Request) error {
	validatable, err := r.Authboss.Core.BodyReader.Read(PageRecoverMiddle, req)
	if err != nil {
		return err
	}

	values := authboss.MustHaveRecoverMiddleValues(validatable)
	token := values.GetToken()

	data := authboss.HTMLData{
		DataRecoverToken: token,
	}

	return r.Authboss.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
}

// EndPost retrieves the token
func (r *Recover) EndPost(w http.ResponseWriter, req *http.Request) error {
	logger := r.RequestLogger(req)

	validatable, err := r.Authboss.Core.BodyReader.Read(PageRecoverEnd, req)
	if err != nil {
		return err
	}

	values := authboss.MustHaveRecoverEndValues(validatable)
	password := values.GetPassword()
	token := values.GetToken()

	if errs := validatable.Validate(); errs != nil {
		logger.Info("recovery validation failed")
		data := authboss.HTMLData{
			authboss.DataValidation: authboss.ErrorMap(errs),
			DataRecoverToken:        token,
		}
		return r.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
	}

	rawToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		logger.Infof("invalid recover token submitted, base64 decode failed: %+v", err)
		return r.invalidToken(PageRecoverEnd, w, req)
	}

	hash := sha512.Sum512(rawToken)
	dbToken := base64.StdEncoding.EncodeToString(hash[:])

	storer := authboss.EnsureCanRecover(r.Authboss.Config.Storage.Server)
	user, err := storer.LoadByRecoverToken(req.Context(), dbToken)
	if err == authboss.ErrUserNotFound {
		logger.Info("invalid recover token submitted, user not found")
		return r.invalidToken(PageRecoverEnd, w, req)
	} else if err != nil {
		return err
	}

	if time.Now().UTC().After(user.GetRecoverExpiry()) {
		logger.Infof("invalid recover token submitted, already expired: %+v", err)
		return r.invalidToken(PageRecoverEnd, w, req)
	}

	pass, err := bcrypt.GenerateFromPassword([]byte(password), r.Authboss.Config.Modules.BCryptCost)
	if err != nil {
		return err
	}

	user.PutPassword(string(pass))
	user.PutRecoverToken("")                // Don't allow another recovery
	user.PutRecoverExpiry(time.Now().UTC()) // Put current time for those DBs that can't handle 0 time

	if err := storer.Save(req.Context(), user); err != nil {
		return err
	}

	successMsg := "Successfully updated password"
	if r.Authboss.Config.Modules.RecoverLoginAfterRecovery {
		authboss.PutSession(w, authboss.SessionKey, user.GetPID())
		successMsg += " and logged in"
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: r.Authboss.Config.Paths.RecoverOK,
		Success:      successMsg,
	}
	return r.Authboss.Config.Core.Redirector.Redirect(w, req, ro)
}

func (r *Recover) invalidToken(page string, w http.ResponseWriter, req *http.Request) error {
	errors := []error{errors.New("recovery token is invalid")}
	data := authboss.HTMLData{authboss.DataValidation: authboss.ErrorMap(errors)}
	return r.Authboss.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
}

// GenerateToken appropriate for user recovery
func GenerateToken() (hash, token string, err error) {
	rawToken := make([]byte, 32)
	if _, err = rand.Read(rawToken); err != nil {
		return "", "", err
	}
	sum := sha512.Sum512(rawToken)

	return base64.StdEncoding.EncodeToString(sum[:]), base64.URLEncoding.EncodeToString(rawToken), nil
}
