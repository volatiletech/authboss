package register

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

func setup() *Register {
	authboss.Cfg = authboss.NewConfig()
	authboss.Cfg.Layout = template.Must(template.New("").Parse(`{{template "authboss" .}}`))
	authboss.Cfg.XSRFName = "xsrf"
	authboss.Cfg.XSRFMaker = func(_ http.ResponseWriter, _ *http.Request) string {
		return "xsrfvalue"
	}
	authboss.Cfg.ConfirmFields = []string{"password", "confirm_password"}
	authboss.Cfg.Storer = mocks.NewMockStorer()

	reg := Register{}
	if err := reg.Initialize(); err != nil {
		panic(err)
	}

	return &reg
}

func TestRegister(t *testing.T) {
	authboss.Cfg = authboss.NewConfig()
	authboss.Cfg.Storer = mocks.NewMockStorer()
	r := Register{}

	if err := r.Initialize(); err != nil {
		t.Error(err)
	}

	if r.Routes()["/register"] == nil {
		t.Error("Expected a register handler at /register.")
	}

	sto := r.Storage()
	if sto[authboss.Cfg.PrimaryID] != authboss.String {
		t.Error("Wanted primary ID to be a string.")
	}
	if sto[authboss.StorePassword] != authboss.String {
		t.Error("Wanted password to be a string.")
	}
}

func TestRegisterGet(t *testing.T) {
	reg := setup()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/register", nil)
	ctx, _ := authboss.ContextFromRequest(r)
	ctx.SessionStorer = mocks.NewMockClientStorer()

	if err := reg.registerHandler(ctx, w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("It should have written a 200:", w.Code)
	}

	if w.Body.Len() == 0 {
		t.Error("It should have wrote a response.")
	}

	if str := w.Body.String(); !strings.Contains(str, "<form") {
		t.Error("It should have rendered a nice form:", str)
	} else if !strings.Contains(str, `name="`+authboss.Cfg.PrimaryID) {
		t.Error("Form should contain the primary ID:", str)
	}
}

func TestRegisterPostValidationErrs(t *testing.T) {
	reg := setup()

	w := httptest.NewRecorder()
	vals := url.Values{}

	email := "email@address.com"
	vals.Set(authboss.Cfg.PrimaryID, email)
	vals.Set(authboss.StorePassword, "pass")
	vals.Set(authboss.ConfirmPrefix+authboss.StorePassword, "pass2")

	r, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx, _ := authboss.ContextFromRequest(r)
	ctx.SessionStorer = mocks.NewMockClientStorer()

	if err := reg.registerHandler(ctx, w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("It should have written a 200:", w.Code)
	}

	if w.Body.Len() == 0 {
		t.Error("It should have wrote a response.")
	}

	if str := w.Body.String(); !strings.Contains(str, "Does not match password") {
		t.Error("Confirm password should have an error:", str)
	}

	if _, err := authboss.Cfg.Storer.Get(email, authboss.AttributeMeta(reg.Storage())); err != authboss.ErrUserNotFound {
		t.Error("The user should not have been saved.")
	}
}

func TestRegisterPostSuccess(t *testing.T) {
	reg := setup()

	w := httptest.NewRecorder()
	vals := url.Values{}

	email := "email@address.com"
	vals.Set(authboss.Cfg.PrimaryID, email)
	vals.Set(authboss.StorePassword, "pass")
	vals.Set(authboss.ConfirmPrefix+authboss.StorePassword, "pass")

	r, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx, _ := authboss.ContextFromRequest(r)
	ctx.SessionStorer = mocks.NewMockClientStorer()

	if err := reg.registerHandler(ctx, w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusFound {
		t.Error("It should have written a redirect:", w.Code)
	}

	if loc := w.Header().Get("Location"); loc != "/" {
		t.Error("Redirected to the wrong location", loc)
	}

	user, err := authboss.Cfg.Storer.Get(email, authboss.AttributeMeta(reg.Storage()))
	if err == authboss.ErrUserNotFound {
		t.Error("The user have been saved.")
	}

	attrs := authboss.Unbind(user)
	if e, err := attrs.StringErr(authboss.Cfg.PrimaryID); err != nil {
		t.Error(err)
	} else if e != email {
		t.Errorf("Email was not set properly, want: %s, got: %s", email, e)
	}

	if p, err := attrs.StringErr(authboss.StorePassword); err != nil {
		t.Error(err)
	} else if p == "pass" {
		t.Error("Password was not hashed.")
	}
}
