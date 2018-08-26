// Package totp2fa implements two factor auth using time-based
// one time passwords.
package totp2fa

import (
	"bytes"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/otp/twofactor"
)

const (
	otpKeyFormat = "otpauth://totp/%s:%s?issuer=%s&secret=%s"
)

// Session keys
const (
	SessionTOTPSecret     = "totp_secret"
	SessionTOTPPendingPID = "totp_pending"
)

// Pages
const (
	PageTOTPValidate        = "totp2fa_validate"
	PageTOTPValidateSuccess = "totp2fa_validate_success"
)

// Form value constants
const (
	FormValueCode = "code"
)

// Data constants
const (
	DataValidateMode = "validate_mode"
	DataTOTPSecret   = SessionTOTPSecret

	dataValidate        = "validate"
	dataValidateSetup   = "setup"
	dataValidateConfirm = "confirm"
	dataValidateRemove  = "remove"
)

var (
	errNoTOTPEnabled = errors.New("user does not have totp 2fa enabled")
)

// User for TOTP
type User interface {
	twofactor.User

	GetTOTPSecretKey() string
	PutTOTPSecretKey(string)
}

// TOTP implements time based one time passwords
type TOTP struct {
	*authboss.Authboss
}

// Setup the module
func (t *TOTP) Setup() error {
	middleware := authboss.Middleware(t.Authboss, true, false, false)
	t.Authboss.Core.Router.Get("/2fa/totp/setup", middleware(t.Core.ErrorHandler.Wrap(t.GetSetup)))
	t.Authboss.Core.Router.Post("/2fa/totp/setup", middleware(t.Core.ErrorHandler.Wrap(t.PostSetup)))

	t.Authboss.Core.Router.Get("/2fa/totp/qr", middleware(t.Core.ErrorHandler.Wrap(t.GetQRCode)))

	t.Authboss.Core.Router.Get("/2fa/totp/confirm", middleware(t.Core.ErrorHandler.Wrap(t.GetConfirm)))
	t.Authboss.Core.Router.Post("/2fa/totp/confirm", middleware(t.Core.ErrorHandler.Wrap(t.PostConfirm)))

	t.Authboss.Core.Router.Get("/2fa/totp/remove", middleware(t.Core.ErrorHandler.Wrap(t.GetRemove)))
	t.Authboss.Core.Router.Post("/2fa/totp/remove", middleware(t.Core.ErrorHandler.Wrap(t.PostRemove)))

	t.Authboss.Core.Router.Get("/2fa/totp/validate", t.Core.ErrorHandler.Wrap(t.GetValidate))
	t.Authboss.Core.Router.Post("/2fa/totp/validate", t.Core.ErrorHandler.Wrap(t.PostValidate))

	t.Authboss.Events.Before(authboss.EventAuth, t.BeforeAuth)

	return t.Authboss.Core.ViewRenderer.Load(PageTOTPValidate, PageTOTPValidateSuccess)
}

// BeforeAuth stores the user's pid in a special temporary session variable
// and redirects them to the validation endpoint.
func (t *TOTP) BeforeAuth(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	if handled {
		return false, nil
	}

	user := r.Context().Value(authboss.CTXKeyUser).(User)

	if len(user.GetTOTPSecretKey()) == 0 {
		return false, nil
	}

	authboss.PutSession(w, SessionTOTPPendingPID, user.GetPID())

	var query string
	if len(r.URL.RawQuery) != 0 {
		query = "?" + r.URL.RawQuery
	}
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: t.Paths.Mount + "/2fa/totp/validate" + query,
	}
	return true, t.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// GetSetup shows a screen allows a user to opt in to setting up totp 2fa
func (t *TOTP) GetSetup(w http.ResponseWriter, r *http.Request) error {
	authboss.DelSession(w, SessionTOTPSecret)
	data := authboss.HTMLData{DataValidateMode: dataValidateSetup}
	return t.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
}

// PostSetup prepares adds a key to the user's session
func (t *TOTP) PostSetup(w http.ResponseWriter, r *http.Request) error {
	abUser, err := t.CurrentUser(r)
	if err != nil {
		return err
	}

	user := abUser.(User)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.Authboss.Config.Modules.TOTP2FAIssuer,
		AccountName: user.GetEmail(),
	})

	if err != nil {
		return errors.Wrap(err, "failed to create a totp key")
	}

	secret := key.Secret()
	authboss.PutSession(w, SessionTOTPSecret, secret)

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: t.Paths.Mount + "/2fa/totp/confirm",
	}
	return t.Core.Redirector.Redirect(w, r, ro)
}

// GetQRCode responds with a QR code image
func (t *TOTP) GetQRCode(w http.ResponseWriter, r *http.Request) error {
	abUser, err := t.CurrentUser(r)
	if err != nil {
		return err
	}
	user := abUser.(User)

	totpSecret, ok := authboss.GetSession(r, SessionTOTPSecret)

	var key *otp.Key
	if !ok || len(totpSecret) == 0 {
		totpSecret = user.GetTOTPSecretKey()
	}

	key, err = otp.NewKeyFromURL(
		fmt.Sprintf(otpKeyFormat,
			url.PathEscape(t.Authboss.Config.Modules.TOTP2FAIssuer),
			url.PathEscape(user.GetEmail()),
			url.QueryEscape(t.Authboss.Config.Modules.TOTP2FAIssuer),
			url.QueryEscape(totpSecret),
		))

	if err != nil {
		return errors.Wrap(err, "failed to reconstruct key from session key: %s")
	}

	image, err := key.Image(200, 200)
	if err != nil {
		return errors.Wrap(err, "failed to create totp qr code")
	}

	buf := &bytes.Buffer{}
	if err = png.Encode(buf, image); err != nil {
		return errors.Wrap(err, "failed to encode qr code to png")
	}

	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, buf)
	return err
}

// GetConfirm requests a user to enter their totp code
func (t *TOTP) GetConfirm(w http.ResponseWriter, r *http.Request) error {
	totpSecret, ok := authboss.GetSession(r, SessionTOTPSecret)
	if !ok {
		return errors.New("request failed, no totp secret present in session")
	}

	data := authboss.HTMLData{
		DataValidateMode: dataValidateConfirm,
		DataTOTPSecret:   totpSecret,
	}
	return t.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
}

// PostConfirm finally activates totp if the code matches
func (t *TOTP) PostConfirm(w http.ResponseWriter, r *http.Request) error {
	abUser, err := t.CurrentUser(r)
	if err != nil {
		return err
	}
	user := abUser.(User)

	totpSecret, ok := authboss.GetSession(r, SessionTOTPSecret)
	if !ok {
		return errors.New("request failed, no totp secret present in session")
	}

	validator, err := t.Authboss.Config.Core.BodyReader.Read(PageTOTPValidate, r)
	if err != nil {
		return err
	}

	totpCodeValues := MustHaveTOTPCodeValues(validator)
	inputCode := totpCodeValues.GetCode()

	ok = totp.Validate(inputCode, totpSecret)
	if !ok {
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValueCode: []string{"2fa code was invalid"}},
			DataValidateMode:        dataValidateConfirm,
			DataTOTPSecret:          totpSecret,
		}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
	}

	codes, err := twofactor.GenerateRecoveryCodes()
	if err != nil {
		return err
	}

	crypted, err := twofactor.BCryptRecoveryCodes(codes)
	if err != nil {
		return err
	}

	// Save the user which activates 2fa
	user.PutTOTPSecretKey(totpSecret)
	user.PutRecoveryCodes(twofactor.EncodeRecoveryCodes(crypted))
	if err = t.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	authboss.DelSession(w, SessionTOTPSecret)

	logger := t.RequestLogger(r)
	logger.Infof("user %s enabled totp 2fa", user.GetPID())

	data := authboss.HTMLData{
		twofactor.DataRecoveryCodes: codes,
		DataValidateMode:            dataValidateConfirm,
	}

	return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidateSuccess, data)
}

// GetRemove starts removal
func (t *TOTP) GetRemove(w http.ResponseWriter, r *http.Request) error {
	data := authboss.HTMLData{DataValidateMode: dataValidateRemove}
	return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
}

// PostRemove removes totp
func (t *TOTP) PostRemove(w http.ResponseWriter, r *http.Request) error {
	user, ok, err := t.validate(r)
	switch {
	case err == errNoTOTPEnabled:
		data := authboss.HTMLData{
			authboss.DataErr: "totp 2fa not active",
			DataValidateMode: dataValidateRemove,
		}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
	case err != nil:
		return err
	case !ok:
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValueCode: []string{"2fa code was invalid"}},
			DataValidateMode:        dataValidateRemove,
		}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
	}

	authboss.PutSession(w, authboss.Session2FA, "")
	user.PutTOTPSecretKey("")
	if err = t.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	logger := t.RequestLogger(r)
	logger.Infof("user %s disabled totp 2fa", user.GetPID())

	data := authboss.HTMLData{DataValidateMode: dataValidateRemove}
	return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidateSuccess, data)
}

// GetValidate shows a page to enter a code into
func (t *TOTP) GetValidate(w http.ResponseWriter, r *http.Request) error {
	data := authboss.HTMLData{DataValidateMode: dataValidate}
	return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
}

// PostValidate redirects on success
func (t *TOTP) PostValidate(w http.ResponseWriter, r *http.Request) error {
	logger := t.RequestLogger(r)

	user, ok, err := t.validate(r)
	switch {
	case err == errNoTOTPEnabled:
		logger.Infof("user %s totp failure (not enabled)", user.GetPID())
		data := authboss.HTMLData{
			authboss.DataErr: "totp 2fa not active",
			DataValidateMode: dataValidate,
		}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
	case err != nil:
		return err
	case !ok:
		logger.Infof("user %s totp 2fa failure (wrong code)", user.GetPID())
		data := authboss.HTMLData{
			authboss.DataErr: "totp 2fa code incorrect",
			DataValidateMode: dataValidate,
		}
		return t.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageTOTPValidate, data)
	}

	authboss.PutSession(w, authboss.SessionKey, user.GetPID())
	authboss.PutSession(w, authboss.Session2FA, "totp")
	authboss.DelSession(w, authboss.SessionHalfAuthKey)
	authboss.DelSession(w, SessionTOTPPendingPID)
	authboss.DelSession(w, SessionTOTPSecret)

	logger.Infof("user %s totp 2fa success", user.GetPID())

	ro := authboss.RedirectOptions{
		Code:             http.StatusTemporaryRedirect,
		Success:          "Successfully Authenticated",
		RedirectPath:     t.Authboss.Config.Paths.AuthLoginOK,
		FollowRedirParam: true,
	}
	return t.Authboss.Core.Redirector.Redirect(w, r, ro)
}

func (t *TOTP) validate(r *http.Request) (User, bool, error) {
	logger := t.RequestLogger(r)
	var abUser authboss.User
	var err error

	if pid, ok := authboss.GetSession(r, SessionTOTPPendingPID); ok && len(pid) != 0 {
		abUser, err = t.Authboss.Config.Storage.Server.Load(r.Context(), pid)
	} else {
		abUser, err = t.CurrentUser(r)
	}
	if err != nil {
		return nil, false, err
	}

	user := abUser.(User)

	secret := user.GetTOTPSecretKey()
	if len(secret) == 0 {
		return nil, false, errNoTOTPEnabled
	}

	validator, err := t.Authboss.Config.Core.BodyReader.Read(PageTOTPValidate, r)
	if err != nil {
		return nil, false, err
	}

	totpCodeValues := MustHaveTOTPCodeValues(validator)

	if recoveryCode := totpCodeValues.GetRecoveryCode(); len(recoveryCode) != 0 {
		var ok bool
		recoveryCodes := twofactor.DecodeRecoveryCodes(user.GetRecoveryCodes())
		recoveryCodes, ok = twofactor.UseRecoveryCode(recoveryCodes, recoveryCode)

		if ok {
			logger.Infof("user %s used recovery code instead of sms2fa", user.GetPID())
			user.PutRecoveryCodes(twofactor.EncodeRecoveryCodes(recoveryCodes))
			if err := t.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
				return nil, false, err
			}
		}

		return user, ok, nil
	}

	input := totpCodeValues.GetCode()

	return user, totp.Validate(input, secret), nil
}
