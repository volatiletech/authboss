// Package sms2fa implements two factor auth using
// sms-transmitted one time passwords.
package sms2fa

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/otp/twofactor"
)

// Session keys
const (
	SessionSMSNumber     = "sms_number"
	SessionSMSSecret     = "sms_secret"
	SessionSMSLast       = "sms_last"
	SessionSMSPendingPID = "sms_pending"
)

// Form value constants
const (
	FormValueCode        = "code"
	FormValuePhoneNumber = "phone_number"
)

// Pages
const (
	PageSMSValidate        = "sms2fa_validate"
	PageSMSValidateSuccess = "sms2fa_validate_success"
)

// Data constants
const (
	DataValidateMode   = "validate_mode"
	DataSMSSecret      = SessionSMSSecret
	DataSMSPhoneNumber = "sms_phone_number"

	dataValidate        = "validate"
	dataValidateSetup   = "setup"
	dataValidateConfirm = "confirm"
	dataValidateRemove  = "remove"
)

const (
	smsCodeLength       = 6
	smsRateLimitSeconds = 10
)

var (
	errNoSMSEnabled   = errors.New("user does not have sms 2fa enabled")
	errSMSRateLimit   = errors.New("user sms send rate-limited")
	errBadPhoneNumber = errors.New("bad phone number provided")
)

// User for SMS
type User interface {
	twofactor.User

	GetSMSPhoneNumber() string
	PutSMSPhoneNumber(string)
}

// SMSNumberProvider provides a phone number already attached
// to the user if it exists. This allows a user to be populated
// with a phone-number without the user needing to provide it.
type SMSNumberProvider interface {
	GetSMSPhoneNumberSeed() string
}

// SMSSender sends SMS messages to a phone number
type SMSSender interface {
	Send(number, text string) error
}

// SMS implements time based one time passwords
type SMS struct {
	*authboss.Authboss
	Sender SMSSender
}

// SMSValidator abstracts the send code/resend code/submit code workflow
type SMSValidator struct {
	*SMS
	Action string
}

// Setup the module
func (s *SMS) Setup() error {
	s.Authboss.Core.Router.Get("/2fa/sms/setup", s.Core.ErrorHandler.Wrap(s.GetSetup))
	s.Authboss.Core.Router.Post("/2fa/sms/setup", s.Core.ErrorHandler.Wrap(s.PostSetup))

	confirm := &SMSValidator{SMS: s, Action: dataValidateConfirm}
	s.Authboss.Core.Router.Get("/2fa/sms/confirm", s.Core.ErrorHandler.Wrap(confirm.Get))
	s.Authboss.Core.Router.Post("/2fa/sms/confirm", s.Core.ErrorHandler.Wrap(confirm.Post))

	remove := &SMSValidator{SMS: s, Action: dataValidateRemove}
	s.Authboss.Core.Router.Get("/2fa/sms/remove", s.Core.ErrorHandler.Wrap(remove.Get))
	s.Authboss.Core.Router.Post("/2fa/sms/remove", s.Core.ErrorHandler.Wrap(remove.Post))

	validate := &SMSValidator{SMS: s, Action: dataValidate}
	s.Authboss.Core.Router.Get("/2fa/sms/validate", s.Core.ErrorHandler.Wrap(validate.Get))
	s.Authboss.Core.Router.Post("/2fa/sms/validate", s.Core.ErrorHandler.Wrap(validate.Post))

	s.Authboss.Events.Before(authboss.EventAuth, s.BeforeAuth)

	return s.Authboss.Core.ViewRenderer.Load(PageSMSValidate, PageSMSValidateSuccess)
}

// BeforeAuth stores the user's pid in a special temporary session variable
// and redirects them to the validation endpoint.
func (s *SMS) BeforeAuth(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	if handled {
		return false, nil
	}

	user := r.Context().Value(authboss.CTXKeyUser).(User)

	number := user.GetSMSPhoneNumber()
	if len(number) == 0 {
		return false, nil
	}

	authboss.PutSession(w, SessionSMSPendingPID, user.GetPID())
	err := s.SendCodeToUser(w, r, user.GetPID(), number)
	if err != nil && err != errSMSRateLimit {
		return false, err
	}

	var query string
	if len(r.URL.RawQuery) != 0 {
		query = "?" + r.URL.RawQuery
	}
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: s.Paths.Mount + "/2fa/sms/validate" + query,
	}
	return true, s.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// SendCodeToUser ensures that
func (s *SMS) SendCodeToUser(w http.ResponseWriter, r *http.Request, pid, number string) error {
	code, err := generateRandomCode()
	if err != nil {
		return err
	}

	logger := s.RequestLogger(r)

	if len(number) == 0 {
		return errBadPhoneNumber
	}

	lastStr, ok := authboss.GetSession(r, SessionSMSLast)
	suppress := false
	if ok {
		last, err := strconv.ParseInt(lastStr, 10, 64)
		if err != nil {
			return err
		}
		suppress = time.Now().UTC().Unix()-last < 10
	}

	if suppress {
		logger.Infof("rate-limited sms for %s to %s", pid, number)
		return errSMSRateLimit
	}

	authboss.PutSession(w, SessionSMSLast, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	authboss.PutSession(w, SessionSMSSecret, code)

	logger.Infof("sending sms for %s to %s", pid, number)
	if err := s.Sender.Send(number, code); err != nil {
		logger.Infof("failed to send sms for %s to %s: %+v", pid, number, err)
		return err
	}

	return nil
}

// GetSetup shows a screen that allows a user to opt in to setting up sms 2fa
// by asking for a phone number that's optionally already filled in.
func (s *SMS) GetSetup(w http.ResponseWriter, r *http.Request) error {
	abUser, err := s.CurrentUser(r)
	if err != nil {
		return err
	}

	data := authboss.HTMLData{DataValidateMode: dataValidateSetup}
	numberProvider, ok := abUser.(SMSNumberProvider)
	if ok {
		if val := numberProvider.GetSMSPhoneNumberSeed(); len(val) != 0 {
			data[DataSMSPhoneNumber] = val
		}
	}

	authboss.DelSession(w, SessionSMSSecret)
	authboss.DelSession(w, SessionSMSNumber)

	return s.Core.Responder.Respond(w, r, http.StatusOK, PageSMSValidate, data)
}

// PostSetup adds the phone number provided to the user's session and sends
// an SMS there.
func (s *SMS) PostSetup(w http.ResponseWriter, r *http.Request) error {
	abUser, err := s.CurrentUser(r)
	if err != nil {
		return err
	}
	user := abUser.(User)

	validator, err := s.Authboss.Config.Core.BodyReader.Read(PageSMSValidate, r)
	if err != nil {
		return err
	}

	smsVals := MustHaveSMSPhoneNumberValue(validator)

	number := smsVals.GetPhoneNumber()
	if len(number) == 0 {
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValuePhoneNumber: []string{"must provide a phone number"}},
			DataValidateMode:        dataValidateSetup,
		}
		return s.Core.Responder.Respond(w, r, http.StatusOK, PageSMSValidate, data)
	}

	authboss.PutSession(w, SessionSMSNumber, number)
	if err = s.SendCodeToUser(w, r, user.GetPID(), number); err != nil {
		return err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: s.Paths.Mount + "/2fa/sms/confirm",
	}
	return s.Core.Redirector.Redirect(w, r, ro)
}

// Get shows an empty page typically, this allows us to prompt
// a second time for the action.
func (s *SMSValidator) Get(w http.ResponseWriter, r *http.Request) error {
	data := authboss.HTMLData{DataValidateMode: s.Action}
	return s.Core.Responder.Respond(w, r, http.StatusOK, PageSMSValidate, data)
}

// Post receives a code in the body and validates it, if the code is
// missing then it sends the code to the user (rate-limited).
func (s *SMSValidator) Post(w http.ResponseWriter, r *http.Request) error {
	var abUser authboss.User
	var err error

	// Get the user, they're either logged in and CurrentUser works, or they're
	// in the middle of logging in and SMSPendingPID is set.
	if pid, ok := authboss.GetSession(r, SessionSMSPendingPID); ok && len(pid) != 0 {
		abUser, err = s.Authboss.Config.Storage.Server.Load(r.Context(), pid)
	} else {
		abUser, err = s.CurrentUser(r)
	}
	if err != nil {
		return err
	}
	user := abUser.(User)

	validator, err := s.Authboss.Config.Core.BodyReader.Read(PageSMSValidate, r)
	if err != nil {
		return err
	}
	smsCodeValues := MustHaveSMSValues(validator)

	var inputCode, recoveryCode string
	inputCode = smsCodeValues.GetCode()

	// Only allow recovery codes on login/remove operations
	if s.Action == dataValidate || s.Action == dataValidateRemove {
		recoveryCode = smsCodeValues.GetRecoveryCode()
	}

	if len(recoveryCode) == 0 && len(inputCode) == 0 {
		return s.sendCode(w, r, user)
	}

	if len(recoveryCode) != 0 {
		return s.validateCode(w, r, user, "", recoveryCode)
	}

	return s.validateCode(w, r, user, inputCode, "")
}

func (s *SMSValidator) sendCode(w http.ResponseWriter, r *http.Request, user User) error {
	var phoneNumber string

	// Get the phone number, when we're confirming the phone number is not
	// yet stored in the user but inside the session.
	switch s.Action {
	case dataValidateConfirm:
		var ok bool
		phoneNumber, ok = authboss.GetSession(r, SessionSMSNumber)
		if !ok {
			return errors.New("request failed, no sms number present in session")
		}

	case dataValidate, dataValidateRemove:
		phoneNumber = user.GetSMSPhoneNumber()
	}

	if len(phoneNumber) == 0 {
		return errors.Errorf("no phone number was available in PostSendCode for user %s", user.GetPID())
	}

	data := authboss.HTMLData{DataValidateMode: s.Action}

	err := s.SendCodeToUser(w, r, user.GetPID(), phoneNumber)
	if err == errSMSRateLimit {
		data[authboss.DataErr] = "please wait a few moments before resending SMS code"
	} else if err != nil {
		return err
	}

	return s.Core.Responder.Respond(w, r, http.StatusOK, PageSMSValidate, data)
}

func (s *SMSValidator) validateCode(w http.ResponseWriter, r *http.Request, user User, inputCode, recoveryCode string) error {
	logger := s.RequestLogger(r)

	var verified bool
	if len(recoveryCode) != 0 {
		var ok bool
		recoveryCodes := twofactor.DecodeRecoveryCodes(user.GetRecoveryCodes())
		recoveryCodes, ok = twofactor.UseRecoveryCode(recoveryCodes, recoveryCode)

		verified = ok

		if verified {
			logger.Infof("user %s used recovery code instead of sms2fa", user.GetPID())
			user.PutRecoveryCodes(twofactor.EncodeRecoveryCodes(recoveryCodes))
			if err := s.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
				return err
			}
		}
	} else {
		code, ok := authboss.GetSession(r, SessionSMSSecret)
		if !ok || len(code) == 0 {
			return errors.Errorf("no code in session for user %s", user.GetPID())
		}

		verified = 1 == subtle.ConstantTimeCompare([]byte(inputCode), []byte(code))
	}

	if !verified {
		logger.Infof("user %s sms 2fa failure (wrong code)", user.GetPID())
		data := authboss.HTMLData{
			authboss.DataValidation: map[string][]string{FormValueCode: []string{"2fa code was invalid"}},
			DataValidateMode:        s.Action,
		}
		return s.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageSMSValidate, data)
	}

	data := authboss.HTMLData{
		DataValidateMode: s.Action,
	}

	switch s.Action {
	case dataValidateConfirm:
		phoneNumber, ok := authboss.GetSession(r, SessionSMSNumber)
		if !ok {
			return errors.New("request failed, no sms number present in session")
		}

		codes, err := twofactor.GenerateRecoveryCodes()
		if err != nil {
			return err
		}

		crypted, err := twofactor.BCryptRecoveryCodes(codes)
		if err != nil {
			return err
		}

		// Save the user which activates 2fa (phone number should be stored from earlier)
		user.PutSMSPhoneNumber(phoneNumber)
		user.PutRecoveryCodes(twofactor.EncodeRecoveryCodes(crypted))
		if err = s.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
			return err
		}

		authboss.DelSession(w, SessionSMSSecret)
		authboss.DelSession(w, SessionSMSNumber)

		logger.Infof("user %s enabled sms 2fa", user.GetPID())
		data[twofactor.DataRecoveryCodes] = codes
	case dataValidateRemove:
		user.PutSMSPhoneNumber("")
		if err := s.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
			return err
		}

		authboss.PutSession(w, authboss.Session2FA, "")

		logger.Infof("user %s disabled sms 2fa", user.GetPID())
	case dataValidate:
		authboss.PutSession(w, authboss.SessionKey, user.GetPID())
		authboss.PutSession(w, authboss.Session2FA, "sms")
		authboss.DelSession(w, authboss.SessionHalfAuthKey)
		authboss.DelSession(w, SessionSMSPendingPID)
		authboss.DelSession(w, SessionSMSSecret)

		logger.Infof("user %s sms 2fa success", user.GetPID())

		ro := authboss.RedirectOptions{
			Code:             http.StatusTemporaryRedirect,
			Success:          "Successfully Authenticated",
			RedirectPath:     s.Authboss.Config.Paths.AuthLoginOK,
			FollowRedirParam: true,
		}
		return s.Authboss.Core.Redirector.Redirect(w, r, ro)
	default:
		return errors.New("unknown action for sms validate")
	}

	return s.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageSMSValidateSuccess, data)
}

// generateRandomCode for sms auth
func generateRandomCode() (code string, err error) {
	sb := new(strings.Builder)

	random := make([]byte, smsCodeLength)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}

	for i := range random {
		sb.WriteByte(random[i]%10 + 48)
	}

	return sb.String(), nil
}
