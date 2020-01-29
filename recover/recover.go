// Package recover implements password reset via e-mail.
package recover

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/volatiletech/authboss"
	"golang.org/x/crypto/bcrypt"
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

	recoverTokenSize  = 64
	recoverTokenSplit = recoverTokenSize / 2
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

	if errs := validatable.Validate(); errs != nil {
		logger.Info("recover validation failed")
		data := authboss.HTMLData{authboss.DataValidation: authboss.ErrorMap(errs)}
		return r.Authboss.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverStart, data)
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

	selector, verifier, token, err := GenerateRecoverCreds()
	if err != nil {
		return err
	}

	ru.PutRecoverSelector(selector)
	ru.PutRecoverVerifier(verifier)
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

	mailURL := r.mailURL(encodedToken)

	email := authboss.Email{
		To:       []string{to},
		From:     r.Authboss.Config.Mail.From,
		FromName: r.Authboss.Config.Mail.FromName,
		Subject:  r.Authboss.Config.Mail.SubjectPrefix + "Password Reset",
	}

	ro := authboss.EmailResponseOptions{
		HTMLTemplate: EmailRecoverHTML,
		TextTemplate: EmailRecoverTxt,
		Data: authboss.HTMLData{
			DataRecoverURL: mailURL,
		},
	}

	logger.Infof("sending recover e-mail to: %s", to)
	if err := r.Authboss.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to recover send e-mail to %s: %+v", to, err)
	}
}

// EndGet shows a password recovery form, and it should have the token that
// the user brought in the query parameters in it on submission.
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
		return r.invalidToken(w, req)
	}

	if len(rawToken) != recoverTokenSize {
		logger.Infof("invalid recover token submitted, size was wrong: %d", len(rawToken))
		return r.invalidToken(w, req)
	}

	selectorBytes := sha512.Sum512(rawToken[:recoverTokenSplit])
	verifierBytes := sha512.Sum512(rawToken[recoverTokenSplit:])
	selector := base64.StdEncoding.EncodeToString(selectorBytes[:])

	storer := authboss.EnsureCanRecover(r.Authboss.Config.Storage.Server)
	user, err := storer.LoadByRecoverSelector(req.Context(), selector)
	if err == authboss.ErrUserNotFound {
		logger.Info("invalid recover token submitted, user not found")
		return r.invalidToken(w, req)
	} else if err != nil {
		return err
	}

	if time.Now().UTC().After(user.GetRecoverExpiry()) {
		logger.Infof("invalid recover token submitted, already expired: %+v", err)
		return r.invalidToken(w, req)
	}

	dbVerifierBytes, err := base64.StdEncoding.DecodeString(user.GetRecoverVerifier())
	if err != nil {
		logger.Infof("invalid recover verifier stored in database: %s", user.GetRecoverVerifier())
		return r.invalidToken(w, req)
	}

	if subtle.ConstantTimeEq(int32(len(verifierBytes)), int32(len(dbVerifierBytes))) != 1 ||
		subtle.ConstantTimeCompare(verifierBytes[:], dbVerifierBytes) != 1 {
		logger.Info("stored recover verifier does not match provided one")
		return r.invalidToken(w, req)
	}

	pass, err := bcrypt.GenerateFromPassword([]byte(password), r.Authboss.Config.Modules.BCryptCost)
	if err != nil {
		return err
	}

	user.PutPassword(string(pass))
	user.PutRecoverSelector("")             // Don't allow another recovery
	user.PutRecoverVerifier("")             // Don't allow another recovery
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

func (r *Recover) invalidToken(w http.ResponseWriter, req *http.Request) error {
	errors := []error{errors.New("recovery token is invalid")}
	data := authboss.HTMLData{authboss.DataValidation: authboss.ErrorMap(errors)}
	return r.Authboss.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
}

func (r *Recover) mailURL(token string) string {
	query := url.Values{FormValueToken: []string{token}}

	if len(r.Config.Mail.RootURL) != 0 {
		return fmt.Sprintf("%s?%s", r.Config.Mail.RootURL+"/recover/end", query.Encode())
	}

	p := path.Join(r.Config.Paths.Mount, "recover/end")
	return fmt.Sprintf("%s%s?%s", r.Config.Paths.RootURL, p, query.Encode())
}

// GenerateRecoverCreds generates pieces needed for user recovery
// selector: hash of the first half of a 64 byte value
// (to be stored in the database and used in SELECT query)
// verifier: hash of the second half of a 64 byte value
// (to be stored in database but never used in SELECT query)
// token: the user-facing base64 encoded selector+verifier
func GenerateRecoverCreds() (selector, verifier, token string, err error) {
	rawToken := make([]byte, recoverTokenSize)
	if _, err = io.ReadFull(rand.Reader, rawToken); err != nil {
		return "", "", "", err
	}
	selectorBytes := sha512.Sum512(rawToken[:recoverTokenSplit])
	verifierBytes := sha512.Sum512(rawToken[recoverTokenSplit:])

	return base64.StdEncoding.EncodeToString(selectorBytes[:]),
		base64.StdEncoding.EncodeToString(verifierBytes[:]),
		base64.URLEncoding.EncodeToString(rawToken),
		nil
}
