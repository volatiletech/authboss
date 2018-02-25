package register

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
)

func TestRegisterInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler
	ab.Config.Storage.Server = &mocks.ServerStorer{}

	reg := &Register{}
	if err := reg.Init(ab); err != nil {
		t.Fatal(err)
	}

	if err := renderer.HasLoadedViews(PageRegister); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/register"); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts("/register"); err != nil {
		t.Error(err)
	}
}

func TestRegisterGet(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	responder := &mocks.Responder{}
	ab.Config.Core.Responder = responder

	a := &Register{ab}
	a.Get(nil, nil)

	if responder.Page != PageRegister {
		t.Error("wanted login page, got:", responder.Page)
	}

	if responder.Status != http.StatusOK {
		t.Error("wanted ok status, got:", responder.Status)
	}
}

type testHarness struct {
	reg *Register
	ab  *authboss.Authboss

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

	harness.ab.Paths.RegisterOK = "/ok"

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.reg = &Register{harness.ab}

	return harness
}

func TestRegisterPostSuccess(t *testing.T) {
	t.Parallel()

	setupMore := func(harness *testHarness) *testHarness {
		harness.ab.Modules.RegisterPreserveFields = []string{"email", "another"}
		harness.bodyReader.Return = mocks.ArbValues{
			Values: map[string]string{
				"email":    "test@test.com",
				"password": "hello world",
				"another":  "value",
			},
		}

		return harness
	}

	t.Run("normal", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp, r)

		if err := h.reg.Post(w, r); err != nil {
			t.Error(err)
		}

		user, ok := h.storer.Users["test@test.com"]
		if !ok {
			t.Error("user was not persisted in the DB")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("hello world")); err != nil {
			t.Error("password was not properly encrypted:", err)
		}

		if user.Arbitrary["another"] != "value" {
			t.Error("arbitrary values not saved")
		}

		if h.session.ClientValues[authboss.SessionKey] != "test@test.com" {
			t.Error("user should have been logged in:", h.session.ClientValues)
		}

		if resp.Code != http.StatusTemporaryRedirect {
			t.Error("code was wrong:", resp.Code)
		}
		if h.redirector.Options.RedirectPath != "/ok" {
			t.Error("redirect path was wrong:", h.redirector.Options.RedirectPath)
		}
	})

	t.Run("handledAfter", func(t *testing.T) {
		t.Parallel()
		h := setupMore(testSetup())

		var afterCalled bool
		h.ab.Events.After(authboss.EventRegister, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			w.WriteHeader(http.StatusTeapot)
			afterCalled = true
			return true, nil
		})

		r := mocks.Request("POST")
		resp := httptest.NewRecorder()
		w := h.ab.NewResponse(resp, r)

		if err := h.reg.Post(w, r); err != nil {
			t.Error(err)
		}

		user, ok := h.storer.Users["test@test.com"]
		if !ok {
			t.Error("user was not persisted in the DB")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("hello world")); err != nil {
			t.Error("password was not properly encrypted:", err)
		}

		if val, ok := h.session.ClientValues[authboss.SessionKey]; ok {
			t.Error("user should not have been logged in:", val)
		}

		if resp.Code != http.StatusTeapot {
			t.Error("code was wrong:", resp.Code)
		}
	})
}

func TestRegisterPostValidationFailure(t *testing.T) {
	t.Parallel()

	h := testSetup()

	// Ensure the below is sorted, the sort normally happens in Init() that we don't call
	h.ab.Modules.RegisterPreserveFields = []string{"another", "email"}
	h.bodyReader.Return = mocks.ArbValues{
		Values: map[string]string{
			"email":    "test@test.com",
			"password": "hello world",
			"another":  "value",
		},
		Errors: []error{
			errors.New("bad password"),
		},
	}

	r := mocks.Request("POST")
	resp := httptest.NewRecorder()
	w := h.ab.NewResponse(resp, r)

	if err := h.reg.Post(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Status != http.StatusOK {
		t.Error("wrong status:", h.responder.Status)
	}
	if h.responder.Page != PageRegister {
		t.Error("rendered wrong page:", h.responder.Page)
	}

	errList := h.responder.Data[authboss.DataValidation].(authboss.ErrorList)
	if e := errList[0].Error(); e != "bad password" {
		t.Error("validation error wrong:", e)
	}

	intfD, ok := h.responder.Data[authboss.DataPreserve]
	if !ok {
		t.Fatal("there was no preserved data")
	}

	d := intfD.(map[string]string)
	if d["email"] != "test@test.com" {
		t.Error("e-mail was not preserved:", d)
	} else if d["another"] != "value" {
		t.Error("another value was not preserved", d)
	} else if _, ok = d["password"]; ok {
		t.Error("password was preserved", d)
	}
}

func TestRegisterPostUserExists(t *testing.T) {
	t.Parallel()

	h := testSetup()

	// Ensure the below is sorted, the sort normally happens in Init() that we don't call
	h.ab.Modules.RegisterPreserveFields = []string{"another", "email"}
	h.storer.Users["test@test.com"] = &mocks.User{}
	h.bodyReader.Return = mocks.ArbValues{
		Values: map[string]string{
			"email":    "test@test.com",
			"password": "hello world",
			"another":  "value",
		},
	}

	r := mocks.Request("POST")
	resp := httptest.NewRecorder()
	w := h.ab.NewResponse(resp, r)

	if err := h.reg.Post(w, r); err != nil {
		t.Error(err)
	}

	if h.responder.Status != http.StatusOK {
		t.Error("wrong status:", h.responder.Status)
	}
	if h.responder.Page != PageRegister {
		t.Error("rendered wrong page:", h.responder.Page)
	}

	errList := h.responder.Data[authboss.DataValidation].(authboss.ErrorList)
	if e := errList[0].Error(); e != "user already exists" {
		t.Error("validation error wrong:", e)
	}

	intfD, ok := h.responder.Data[authboss.DataPreserve]
	if !ok {
		t.Fatal("there was no preserved data")
	}

	d := intfD.(map[string]string)
	if d["email"] != "test@test.com" {
		t.Error("e-mail was not preserved:", d)
	} else if d["another"] != "value" {
		t.Error("another value was not preserved", d)
	} else if _, ok = d["password"]; ok {
		t.Error("password was preserved", d)
	}
}

func TestHasString(t *testing.T) {
	t.Parallel()

	strs := []string{"b", "c", "d", "e"}

	if !hasString(strs, "b") {
		t.Error("should have a")
	}
	if !hasString(strs, "e") {
		t.Error("should have d")
	}

	if hasString(strs, "a") {
		t.Error("should not have a")
	}
	if hasString(strs, "f") {
		t.Error("should not have f")
	}
}

/*
func setup() *Register {
	ab := authboss.New()
	ab.RegisterOKPath = "/regsuccess"
	ab.Layout = template.Must(template.New("").Parse(`{{template "authboss" .}}`))
	ab.XSRFName = "xsrf"
	ab.XSRFMaker = func(_ http.ResponseWriter, _ *http.Request) string {
		return "xsrfvalue"
	}
	ab.ConfirmFields = []string{"password", "confirm_password"}
	ab.Storage.Server = mocks.NewMockStorer()

	reg := Register{}
	if err := reg.Initialize(ab); err != nil {
		panic(err)
	}

	return &reg
}

func TestRegister(t *testing.T) {
	ab := authboss.New()
	ab.Storage.Server = mocks.NewMockStorer()
	r := Register{}
	if err := r.Initialize(ab); err != nil {
		t.Error(err)
	}

	if r.Routes()["/register"] == nil {
		t.Error("Expected a register handler at /register.")
	}

	sto := r.Storage()
	if sto[r.PrimaryID] != authboss.String {
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
	ctx := reg.NewContext()
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
	} else if !strings.Contains(str, `name="`+reg.PrimaryID) {
		t.Error("Form should contain the primary ID:", str)
	}
}

func TestRegisterPostValidationErrs(t *testing.T) {
	reg := setup()

	w := httptest.NewRecorder()
	vals := url.Values{}

	email := "email@address.com"
	vals.Set(reg.PrimaryID, email)
	vals.Set(authboss.StorePassword, "pass")
	vals.Set(authboss.ConfirmPrefix+authboss.StorePassword, "pass2")

	r, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := reg.NewContext()
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

	if _, err := reg.Storer.Get(email); err != authboss.ErrUserNotFound {
		t.Error("The user should not have been saved.")
	}
}

func TestRegisterPostSuccess(t *testing.T) {
	reg := setup()
	reg.Policies = nil

	w := httptest.NewRecorder()
	vals := url.Values{}

	email := "email@address.com"
	vals.Set(reg.PrimaryID, email)
	vals.Set(authboss.StorePassword, "pass")
	vals.Set(authboss.ConfirmPrefix+authboss.StorePassword, "pass")

	r, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := reg.NewContext()
	ctx.SessionStorer = mocks.NewMockClientStorer()

	if err := reg.registerHandler(ctx, w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusFound {
		t.Error("It should have written a redirect:", w.Code)
	}

	if loc := w.Header().Get("Location"); loc != reg.RegisterOKPath {
		t.Error("Redirected to the wrong location", loc)
	}

	user, err := reg.Storer.Get(email)
	if err == authboss.ErrUserNotFound {
		t.Error("The user have been saved.")
	}

	attrs := authboss.Unbind(user)
	if e, err := attrs.StringErr(reg.PrimaryID); err != nil {
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
*/
