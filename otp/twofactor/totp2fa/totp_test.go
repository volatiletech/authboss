package totp2fa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/volatiletech/authboss/otp/twofactor"

	"github.com/pquerna/otp/totp"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
)

func TestTOTPSetup(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}

	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler

	totp := &TOTP{Authboss: ab}
	if err := totp.Setup(); err != nil {
		t.Fatal(err)
	}

	gets := []string{"/2fa/totp/setup", "/2fa/totp/qr", "/2fa/totp/confirm", "/2fa/totp/remove", "/2fa/totp/validate"}
	posts := []string{"/2fa/totp/setup", "/2fa/totp/confirm", "/2fa/totp/remove", "/2fa/totp/validate"}
	if err := router.HasGets(gets...); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts(posts...); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	totp *TOTP
	ab   *authboss.Authboss

	bodyReader *mocks.BodyReader
	responder  *mocks.Responder
	redirector *mocks.Redirector
	session    *mocks.ClientStateRW
	storer     *mocks.ServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.bodyReader = &mocks.BodyReader{}
	harness.redirector = &mocks.Redirector{}
	harness.responder = &mocks.Responder{}
	harness.session = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Config.Paths.AuthLoginOK = "/login/ok"
	harness.ab.Config.Modules.TOTP2FAIssuer = "TOTPTest"

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.totp = &TOTP{harness.ab}

	return harness
}

func TestBeforeAuth(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	handled, err := harness.totp.BeforeAuth(nil, nil, true)
	if handled {
		t.Error("should not be handled")
	}
	if err != nil {
		t.Error(err)
	}

	r := mocks.Request("POST")
	r.URL.RawQuery = "test=query"
	wr := httptest.NewRecorder()
	w := harness.ab.NewResponse(wr)

	user := &mocks.User{Email: "test@test.com"}
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))

	r, err = harness.ab.LoadClientState(w, r)
	handled, err = harness.totp.BeforeAuth(w, r, false)
	if handled {
		t.Error("should not be handled")
	}
	if err != nil {
		t.Error(err)
	}

	user.TOTPSecretKey = "a"
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))

	r, err = harness.ab.LoadClientState(w, r)
	handled, err = harness.totp.BeforeAuth(w, r, false)
	if !handled {
		t.Error("should be handled")
	}
	if err != nil {
		t.Error(err)
	}

	opts := harness.redirector.Options
	if opts.Code != http.StatusTemporaryRedirect {
		t.Error("status wrong:", opts.Code)
	}

	if opts.RedirectPath != "/auth/2fa/totp/validate?test=query" {
		t.Error("redir path wrong:", opts.RedirectPath)
	}
}

func TestGetSetup(t *testing.T) {
	t.Parallel()
	h := testSetup()

	h.session.ClientValues[SessionTOTPSecret] = "a"

	r := mocks.Request("GET")
	wr := httptest.NewRecorder()
	w := h.ab.NewResponse(wr)

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err = h.totp.GetSetup(w, r); err != nil {
		t.Error(err)
	}

	// Flush ClientState
	w.WriteHeader(http.StatusOK)

	if h.session.ClientValues[SessionTOTPSecret] != "" {
		t.Error("session totp secret should be cleared")
	}

	if h.responder.Page != PageTOTPValidate {
		t.Error("page wrong:", h.responder.Page)
	}
	if got := h.responder.Data[DataValidateMode]; got != dataValidateSetup {
		t.Error("data wrong:", got)
	}
}

func TestPostSetup(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r := mocks.Request("GET")
	wr := httptest.NewRecorder()
	w := h.ab.NewResponse(wr)

	user := &mocks.User{Email: "test@test.com"}
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err = h.totp.PostSetup(w, r); err != nil {
		t.Error(err)
	}

	// Flush ClientState
	w.WriteHeader(http.StatusOK)

	opts := h.redirector.Options
	if opts.Code != http.StatusTemporaryRedirect {
		t.Error("status wrong:", opts.Code)
	}

	if opts.RedirectPath != "/auth/2fa/totp/confirm" {
		t.Error("redir path wrong:", opts.RedirectPath)
	}

	if len(h.session.ClientValues[SessionTOTPSecret]) == 0 {
		t.Error("no secret in the session")
	}
}

func TestGetQRCode(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r := mocks.Request("GET")
	wr := httptest.NewRecorder()
	w := h.ab.NewResponse(wr)

	user := &mocks.User{Email: "test@test.com"}
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))

	// No session
	if err := h.totp.GetQRCode(w, r); err == nil {
		t.Error("should fail because there is no totp secret")
	}

	key := makeSecretKey(h, user.Email)
	h.session.ClientValues[SessionTOTPSecret] = key

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err = h.totp.GetQRCode(w, r); err != nil {
		t.Error(err)
	}

	if got := wr.Header().Get("Content-Type"); got != "image/png" {
		t.Error("content type wrong:", got)
	}
	if wr.Body.Len() == 0 {
		t.Error("body should have been sizable")
	}
}

func TestGetConfirm(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r := mocks.Request("GET")
	wr := httptest.NewRecorder()
	w := h.ab.NewResponse(wr)

	// No session
	if err := h.totp.GetConfirm(w, r); err == nil {
		t.Error("should fail because there is no totp secret")
	}

	secret := "secret"
	h.session.ClientValues[SessionTOTPSecret] = secret

	var err error
	r, err = h.ab.LoadClientState(w, r)
	if err = h.totp.GetConfirm(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Page != PageTOTPValidate {
		t.Error("page wrong:", h.responder.Page)
	}
	if got := h.responder.Data[DataValidateMode]; got != dataValidateConfirm {
		t.Error("data wrong:", got)
	}
	if got := h.responder.Data[DataTOTPSecret]; got != secret {
		t.Error("data wrong:", got)
	}
}

func TestPostConfirm(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r := mocks.Request("GET")
	wr := httptest.NewRecorder()
	w := h.ab.NewResponse(wr)

	// No session
	if err := h.totp.PostConfirm(w, r); err == nil {
		t.Error("should fail because there is no totp secret")
	}

	user := &mocks.User{Email: "test@test.com"}
	h.storer.Users[user.Email] = user

	key := makeSecretKey(h, user.Email)
	h.session.ClientValues[SessionTOTPSecret] = key
	h.session.ClientValues[authboss.SessionKey] = user.Email

	code, err := totp.GenerateCode(key, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	h.bodyReader.Return = &mocks.Values{Code: code}

	r, err = h.ab.LoadClientState(w, r)
	if err = h.totp.PostConfirm(w, r); err != nil {
		t.Error(err)
	}

	// Flush client state
	w.WriteHeader(http.StatusOK)

	if len(user.TOTPSecretKey) == 0 {
		t.Error("totp secret key unset")
	}
	if len(user.RecoveryCodes) == 0 {
		t.Error("user recovery codes unset")
	}
	if _, ok := h.session.ClientValues[SessionTOTPSecret]; ok {
		t.Error("session totp secret not deleted")
	}

	if h.responder.Page != PageTOTPValidateSuccess {
		t.Error("page wrong:", h.responder.Page)
	}
	if got := h.responder.Data[DataValidateMode]; got != dataValidateConfirm {
		t.Error("data wrong:", got)
	}
	if got := h.responder.Data[twofactor.DataRecoveryCodes].([]string); len(got) == 0 {
		t.Error("data wrong:", got)
	}
}

func TestGetRemove(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r := mocks.Request("GET")
	wr := httptest.NewRecorder()
	w := h.ab.NewResponse(wr)

	if err := h.totp.GetRemove(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Page != PageTOTPValidate {
		t.Error("page wrong:", h.responder.Page)
	}
	if got := h.responder.Data[DataValidateMode]; got != dataValidateRemove {
		t.Error("data wrong:", got)
	}
}

func TestPostRemove(t *testing.T) {
	t.Parallel()

	setupMore := func(h *testHarness) *mocks.User {
		user := &mocks.User{Email: "test@test.com"}
		h.storer.Users[user.Email] = user
		h.session.ClientValues[authboss.SessionKey] = user.Email

		return user
	}

	t.Run("no totp activated", func(t *testing.T) {
		h := testSetup()
		r := mocks.Request("GET")
		wr := httptest.NewRecorder()
		w := h.ab.NewResponse(wr)

		setupMore(h)

		var err error
		r, err = h.ab.LoadClientState(w, r)
		if err != nil {
			t.Fatal(err)
		}

		// No session
		if err := h.totp.PostRemove(w, r); err != nil {
			t.Fatal(err)
		}

		if h.responder.Page != PageTOTPValidate {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[DataValidateMode]; got != dataValidateRemove {
			t.Error("data wrong:", got)
		}
		if got := h.responder.Data[authboss.DataErr]; got != "totp 2fa not active" {
			t.Error("data wrong:", got)
		}
	})

	t.Run("wrong code", func(t *testing.T) {
		h := testSetup()
		r := mocks.Request("GET")
		wr := httptest.NewRecorder()
		w := h.ab.NewResponse(wr)

		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret

		h.bodyReader.Return = mocks.Values{Code: "wrong"}

		var err error
		r, err = h.ab.LoadClientState(w, r)
		if err != nil {
			t.Fatal(err)
		}

		if err := h.totp.PostRemove(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Page != PageTOTPValidate {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[DataValidateMode]; got != dataValidateRemove {
			t.Error("data wrong:", got)
		}
		if got := h.responder.Data[authboss.DataValidation].(map[string][]string); got[FormValueCode][0] != "2fa code was invalid" {
			t.Error("data wrong:", got)
		}
	})

	t.Run("ok-code", func(t *testing.T) {
		h := testSetup()
		r := mocks.Request("GET")
		wr := httptest.NewRecorder()
		w := h.ab.NewResponse(wr)

		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret

		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		h.bodyReader.Return = mocks.Values{Code: code}

		h.session.ClientValues[authboss.Session2FA] = "totp"

		r, err = h.ab.LoadClientState(w, r)
		if err != nil {
			t.Fatal(err)
		}

		if err := h.totp.PostRemove(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Page != PageTOTPValidateSuccess {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[DataValidateMode]; got != dataValidateRemove {
			t.Error("data wrong:", got)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		if _, ok := h.session.ClientValues[authboss.Session2FA]; ok {
			t.Error("session 2fa should be cleared")
		}
	})
}

func TestGetValidate(t *testing.T) {
	t.Parallel()
	h := testSetup()

	r := mocks.Request("GET")
	wr := httptest.NewRecorder()
	w := h.ab.NewResponse(wr)

	if err := h.totp.GetValidate(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Page != PageTOTPValidate {
		t.Error("page wrong:", h.responder.Page)
	}
	if got := h.responder.Data[DataValidateMode]; got != dataValidate {
		t.Error("data wrong:", got)
	}
}

func TestPostValidate(t *testing.T) {
	t.Parallel()

	setupMore := func(h *testHarness) *mocks.User {
		user := &mocks.User{Email: "test@test.com"}
		h.storer.Users[user.Email] = user
		h.session.ClientValues[authboss.SessionKey] = user.Email

		return user
	}

	t.Run("no totp activated", func(t *testing.T) {
		h := testSetup()
		r := mocks.Request("GET")
		wr := httptest.NewRecorder()
		w := h.ab.NewResponse(wr)

		setupMore(h)

		var err error
		r, err = h.ab.LoadClientState(w, r)
		if err != nil {
			t.Fatal(err)
		}

		// No session
		if err := h.totp.PostValidate(w, r); err != nil {
			t.Fatal(err)
		}

		if h.responder.Page != PageTOTPValidate {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[DataValidateMode]; got != dataValidate {
			t.Error("data wrong:", got)
		}
		if got := h.responder.Data[authboss.DataErr]; got != "totp 2fa not active" {
			t.Error("data wrong:", got)
		}
	})

	t.Run("wrong code", func(t *testing.T) {
		h := testSetup()
		r := mocks.Request("GET")
		wr := httptest.NewRecorder()
		w := h.ab.NewResponse(wr)

		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret

		h.bodyReader.Return = mocks.Values{Code: "wrong"}

		var err error
		r, err = h.ab.LoadClientState(w, r)
		if err != nil {
			t.Fatal(err)
		}

		if err := h.totp.PostValidate(w, r); err != nil {
			t.Error(err)
		}

		if h.responder.Page != PageTOTPValidate {
			t.Error("page wrong:", h.responder.Page)
		}
		if got := h.responder.Data[DataValidateMode]; got != dataValidate {
			t.Error("data wrong:", got)
		}
		if got := h.responder.Data[authboss.DataValidation].(map[string][]string); got[FormValueCode][0] != "2fa code was invalid" {
			t.Error("data wrong:", got)
		}
	})

	t.Run("ok-recovery", func(t *testing.T) {
		h := testSetup()
		r := mocks.Request("GET")
		wr := httptest.NewRecorder()
		w := h.ab.NewResponse(wr)

		user := setupMore(h)
		secret := makeSecretKey(h, user.Email)
		user.TOTPSecretKey = secret

		codes, err := twofactor.GenerateRecoveryCodes()
		if err != nil {
			t.Fatal(err)
		}
		b, err := bcrypt.GenerateFromPassword([]byte(codes[0]), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		user.RecoveryCodes = string(b)

		h.bodyReader.Return = mocks.Values{Recovery: codes[0]}

		h.session.ClientValues[SessionTOTPPendingPID] = user.Email
		h.session.ClientValues[SessionTOTPSecret] = "a"
		h.session.ClientValues[authboss.SessionHalfAuthKey] = "a"

		r, err = h.ab.LoadClientState(w, r)
		if err != nil {
			t.Fatal(err)
		}

		if err := h.totp.PostValidate(w, r); err != nil {
			t.Error(err)
		}

		// Flush client state
		w.WriteHeader(http.StatusOK)

		if pid := h.session.ClientValues[authboss.SessionKey]; pid != user.Email {
			t.Error("session pid should be set:", pid)
		}
		if twofa := h.session.ClientValues[authboss.Session2FA]; twofa != "totp" {
			t.Error("session 2fa should be totp:", twofa)
		}

		cleared := []string{SessionTOTPSecret, SessionTOTPPendingPID, authboss.SessionHalfAuthKey}
		for _, c := range cleared {
			if _, ok := h.session.ClientValues[c]; ok {
				t.Error(c, "was not cleared")
			}
		}

		opts := h.redirector.Options
		if opts.Code != http.StatusTemporaryRedirect {
			t.Error("status wrong:", opts.Code)
		}
		if !opts.FollowRedirParam {
			t.Error("it should follow redirects")
		}
		if opts.RedirectPath != h.ab.Paths.AuthLoginOK {
			t.Error("path wrong:", opts.RedirectPath)
		}
	})
}

func makeSecretKey(h *testHarness, email string) string {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      h.totp.Modules.TOTP2FAIssuer,
		AccountName: email,
	})
	if err != nil {
		panic(err)
	}

	return key.Secret()
}
