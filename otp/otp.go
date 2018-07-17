// Package otp allows authentication through a one time password
// instead of a traditional password.
package otp

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/volatiletech/authboss"
	"golang.org/x/crypto/bcrypt"
)

const (
	// PageLogin is for identifying the login page for parsing & validation
	PageLogin = "loginotp"
	// PageAdd is for adding an otp to the user
	PageAdd = "addotp"
	// PageClear is for deleting all the otps from the user
	PageClear = "clearotp"

	// DataNumberOTPs shows the number of otps for add/clear operations
	DataNumberOTPs = "notps"
	// DataNewOTP shows the new otp that was added
	DataOTP = "otp"
)

// User for one time passwords
type User interface {
	// GetOTPs retrieves a string of comma separated bcrypt'd one time passwords
	GetOTPs() string
	// PutOTPs puts a string of comma separated bcrypt'd one time passwords
	PutOTPs(string)
}

// MustBeOTPable ensures the user can use one time passwords
func MustBeOTPable(user authboss.User) User {
	u, ok := user.(User)
	if !ok {
		panic(fmt.Sprintf("could not upgrade user to an authable user, type: %T", u))
	}

	return u
}

func init() {
	authboss.RegisterModule("otp", &OTP{})
}

// OTP module
type OTP struct {
	*authboss.Authboss
}

// Init module
func (o *OTP) Init(ab *authboss.Authboss) (err error) {
	o.Authboss = ab

	if err = o.Authboss.Config.Core.ViewRenderer.Load(PageLogin, PageAdd, PageClear); err != nil {
		return err
	}

	o.Authboss.Config.Core.Router.Get("/otp/login", o.Authboss.Core.ErrorHandler.Wrap(o.LoginGet))
	o.Authboss.Config.Core.Router.Post("/otp/login", o.Authboss.Core.ErrorHandler.Wrap(o.LoginPost))

	middleware := authboss.Middleware(ab, true, false)
	o.Authboss.Config.Core.Router.Get("/otp/add", middleware(o.Authboss.Core.ErrorHandler.Wrap(o.AddGet)))
	o.Authboss.Config.Core.Router.Post("/otp/add", middleware(o.Authboss.Core.ErrorHandler.Wrap(o.AddPost)))

	o.Authboss.Config.Core.Router.Get("/otp/clear", middleware(o.Authboss.Core.ErrorHandler.Wrap(o.ClearGet)))
	o.Authboss.Config.Core.Router.Post("/otp/clear", middleware(o.Authboss.Core.ErrorHandler.Wrap(o.ClearPost)))

	return nil
}

// LoginGet simply displays the login form
func (o *OTP) LoginGet(w http.ResponseWriter, r *http.Request) error {
	return o.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, nil)
}

// LoginPost attempts to validate the credentials passed in
// to log in a user.
func (o *OTP) LoginPost(w http.ResponseWriter, r *http.Request) error {
	logger := o.RequestLogger(r)

	validatable, err := o.Authboss.Core.BodyReader.Read(PageLogin, r)
	if err != nil {
		return err
	}

	// Skip validation since all the validation happens during the database lookup and
	// password check.
	creds := authboss.MustHaveUserValues(validatable)

	pid := creds.GetPID()
	pidUser, err := o.Authboss.Storage.Server.Load(r.Context(), pid)
	if err == authboss.ErrUserNotFound {
		logger.Infof("failed to load user requested by pid: %s", pid)
		data := authboss.HTMLData{authboss.DataErr: "Invalid Credentials"}
		return o.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	} else if err != nil {
		return err
	}

	otpUser := MustBeOTPable(pidUser)
	passwords := decodeOTPs(otpUser.GetOTPs())

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, pidUser))

	input := creds.GetPassword()
	matchPassword := -1
	handled := false
	for i, p := range passwords {
		err = bcrypt.CompareHashAndPassword([]byte(p), []byte(input))
		if err == nil {
			matchPassword = i
			break
		}
	}

	if matchPassword < 0 {
		handled, err = o.Authboss.Events.FireAfter(authboss.EventAuthFail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		logger.Infof("user %s failed to log in with otp", pid)
		data := authboss.HTMLData{authboss.DataErr: "Invalid Credentials"}
		return o.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	}

	passwords[matchPassword] = passwords[len(passwords)-1]
	passwords = passwords[:len(passwords)-1]
	otpUser.PutOTPs(encodeOTPs(passwords))
	if err = o.Authboss.Config.Storage.Server.Save(r.Context(), pidUser); err != nil {
		return err
	}

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, validatable))

	handled, err = o.Events.FireBefore(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	logger.Infof("user %s logged in via otp", pid)
	authboss.PutSession(w, authboss.SessionKey, pid)
	authboss.DelSession(w, authboss.SessionHalfAuthKey)

	handled, err = o.Authboss.Events.FireAfter(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	ro := authboss.RedirectOptions{
		Code:             http.StatusTemporaryRedirect,
		RedirectPath:     o.Authboss.Paths.AuthLoginOK,
		FollowRedirParam: true,
	}
	return o.Authboss.Core.Redirector.Redirect(w, r, ro)
}

// AddGet shows how many passwords exist and allows the user to create a new one
func (o *OTP) AddGet(w http.ResponseWriter, r *http.Request) error {
	logger := o.RequestLogger(r)

	user, err := o.Authboss.CurrentUser(r)
	if err != nil {
		return err
	}

	otpUser := MustBeOTPable(user)
	ln := strconv.Itoa(len(decodeOTPs(otpUser.GetOTPs())))

	return o.Core.Responder.Respond(w, r, http.StatusOK, PageAdd, authboss.HTMLData{NumberOTPS: ln})
}

// AddPost adds a new password to the user and displays it
func (o *OTP) AddPost(w http.ResponseWriter, r *http.Request) error {
	logger := o.RequestLogger(r)

	user, err := o.Authboss.CurrentUser(r)
	if err != nil {
		return err
	}

	// GENERATE AN OTP
	panic("otp not generated")
	otp := ""

	otpUser := MustBeOTPable(user)
	currentOTPs := decodeOTPs(otpUser.GetOTPs())
	currentOTPs = append(currentOTPs, otp)
	otpUser.PutOTPs(encodeOTPs(currentOTPs))

	if err := o.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	return o.Core.Responder.Respond(w, r, http.StatusOK, PageAdd, authboss.HTMLData{DataOTP: otp})
}

// ClearGet shows how many passwords exist and allows the user to clear them all
func (o *OTP) ClearGet(w http.ResponseWriter, r *http.Request) error {
	return o.Core.Responder.Respond(w, r, http.StatusOK, PageClear, nil)
}

// ClearPost clears all otps that are stored for the user.
func (o *OTP) ClearPost(w http.ResponseWriter, r *http.Request) error {
	panic("not implemented")
	return nil
}

func encodeOTPs(otps []string) string {
	return strings.Join(otps, ",")
}

func decodeOTPs(otps string) []string {
	if len(otps) == 0 {
		return nil
	}

	return strings.Split(otps, ",")
}
