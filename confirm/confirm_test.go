package confirm

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
)

func TestInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.MailRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler

	c := &Confirm{}
	if err := c.Init(ab); err != nil {
		t.Fatal(err)
	}

	if err := renderer.HasLoadedViews(EmailConfirmHTML, EmailConfirmTxt); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/confirm"); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	confirm *Confirm
	ab      *authboss.Authboss

	bodyReader *mocks.BodyReader
	mailer     *mocks.Emailer
	redirector *mocks.Redirector
	renderer   *mocks.Renderer
	responder  *mocks.Responder
	session    *mocks.ClientStateRW
	storer     *mocks.ServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.bodyReader = &mocks.BodyReader{}
	harness.mailer = &mocks.Emailer{}
	harness.redirector = &mocks.Redirector{}
	harness.renderer = &mocks.Renderer{}
	harness.responder = &mocks.Responder{}
	harness.session = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Paths.ConfirmOK = "/confirm/ok"
	harness.ab.Paths.ConfirmNotOK = "/confirm/not/ok"

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Mailer = harness.mailer
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Core.MailRenderer = harness.renderer
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.confirm = &Confirm{harness.ab}

	return harness
}

func TestPreventAuthAllow(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Confirmed: true,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.PreventAuth(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if handled {
		t.Error("it should not have been handled")
	}
}

func TestPreventDisallow(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mocks.User{
		Confirmed: false,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.PreventAuth(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if !handled {
		t.Error("it should have been handled")
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("redirect did not occur")
	}

	if p := harness.redirector.Options.RedirectPath; p != "/confirm/not/ok" {
		t.Error("redirect path was wrong:", p)
	}
}

func TestStartConfirmationWeb(t *testing.T) {
	// no t.Parallel(), global var mangling

	oldConfirm := goConfirmEmail
	goConfirmEmail = func(c *Confirm, ctx context.Context, to, token string) {
		c.SendConfirmEmail(ctx, to, token)
	}

	defer func() {
		goConfirmEmail = oldConfirm
	}()

	harness := testSetup()

	user := &mocks.User{Email: "test@test.com"}
	harness.storer.Users["test@test.com"] = user

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.StartConfirmationWeb(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if !handled {
		t.Error("it should always be handled")
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("redirect did not occur")
	}

	if p := harness.redirector.Options.RedirectPath; p != "/confirm/not/ok" {
		t.Error("redirect path was wrong:", p)
	}

	if to := harness.mailer.Email.To[0]; to != "test@test.com" {
		t.Error("mailer sent e-mail to wrong person:", to)
	}
}

func TestGetSuccess(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	hash, token, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	user := &mocks.User{Email: "test@test.com", Confirmed: false, ConfirmToken: hash}
	harness.storer.Users["test@test.com"] = user
	harness.bodyReader.Return = mocks.Values{
		Token: token,
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != harness.ab.Paths.ConfirmOK {
		t.Error("redir path was wrong:", p)
	}

	if len(user.ConfirmToken) != 0 {
		t.Error("the confirm token should have been erased")
	}
	if !user.Confirmed {
		t.Error("the user should have been confirmed")
	}
}

func TestGetValidationFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	harness.bodyReader.Return = mocks.Values{
		Errors: []error{errors.New("fail")},
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != harness.ab.Paths.ConfirmNotOK {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Failure; reason != "Invalid confirm token." {
		t.Error("reason for failure was wrong:", reason)
	}
}

func TestGetBase64DecodeFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	harness.bodyReader.Return = mocks.Values{
		Token: "5",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != harness.ab.Paths.ConfirmNotOK {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Failure; reason != "Invalid confirm token." {
		t.Error("reason for failure was wrong:", reason)
	}
}

func TestGetUserNotFoundFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	_, token, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	harness.bodyReader.Return = mocks.Values{
		Token: token,
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != harness.ab.Paths.ConfirmNotOK {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Failure; reason != "Invalid confirm token." {
		t.Error("reason for failure was wrong:", reason)
	}
}

func TestMiddlewareAllow(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	called := false
	server := Middleware(ab, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	user := &mocks.User{
		Confirmed: true,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	server.ServeHTTP(w, r)

	if !called {
		t.Error("The user should have been allowed through")
	}
}

func TestMiddlewareDisallow(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	ab.Config.Core.Logger = mocks.Logger{}
	called := false
	server := Middleware(ab, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	user := &mocks.User{
		Confirmed: false,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	server.ServeHTTP(w, r)

	if called {
		t.Error("The user should not have been allowed through")
	}
}

func TestGenerateToken(t *testing.T) {
	t.Parallel()

	hash, token, err := GenerateToken()
	if err != nil {
		t.Error(err)
	}

	// base64 length: n = 64; 4*(64/3) = 85.3; round to nearest 4: 88
	if len(hash) != 88 {
		t.Errorf("string length was wrong (%d): %s", len(hash), hash)
	}

	// base64 length: n = 32; 4*(32/3) = 42.6; round to nearest 4: 44
	if len(token) != 44 {
		t.Errorf("string length was wrong (%d): %s", len(token), token)
	}

	rawToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Error(err)
	}

	rawHash, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Error(err)
	}

	checkHash := sha512.Sum512(rawToken)
	if 0 != bytes.Compare(checkHash[:], rawHash) {
		t.Error("expected hashes to match")
	}
}

/*
func setup() *Confirm {
	ab := authboss.New()
	ab.Storage.Server = mocks.NewMockStorer()
	ab.LayoutHTMLEmail = template.Must(template.New("").Parse(`email ^_^`))
	ab.LayoutTextEmail = template.Must(template.New("").Parse(`email`))

	c := &Confirm{}
	if err := c.Initialize(ab); err != nil {
		panic(err)
	}
	return c
}

func TestConfirm_Initialize(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	c := &Confirm{}
	if err := c.Initialize(ab); err == nil {
		t.Error("Should cry about not having a storer.")
	}

	c = setup()

	if c.emailHTMLTemplates == nil {
		t.Error("Missing HTML email templates")
	}
	if c.emailTextTemplates == nil {
		t.Error("Missing text email templates")
	}
}

func TestConfirm_Routes(t *testing.T) {
	t.Parallel()

	c := &Confirm{}
	if c.Routes()["/confirm"] == nil {
		t.Error("Expected confirm route.")
	}
}

func TestConfirm_Storage(t *testing.T) {
	t.Parallel()

	c := &Confirm{Authboss: authboss.New()}
	storage := c.Storage()

	if authboss.String != storage[StoreConfirmToken] {
		t.Error("Expect StoreConfirmToken to be a string.")
	}
	if authboss.Bool != storage[StoreConfirmed] {
		t.Error("Expect StoreConfirmed to be a bool.")
	}
}

func TestConfirm_BeforeGet(t *testing.T) {
	t.Parallel()

	c := setup()
	ctx := c.NewContext()

	if _, err := c.beforeGet(ctx); err == nil {
		t.Error("Should stop the get due to attribute missing:", err)
	}

	ctx.User = authboss.Attributes{
		StoreConfirmed: false,
	}

	if interrupt, err := c.beforeGet(ctx); interrupt != authboss.InterruptAccountNotConfirmed {
		t.Error("Should stop the get due to non-confirm:", interrupt)
	} else if err != nil {
		t.Error(err)
	}

	ctx.User = authboss.Attributes{
		StoreConfirmed: true,
	}

	if interrupt, err := c.beforeGet(ctx); interrupt != authboss.InterruptNone || err != nil {
		t.Error(interrupt, err)
	}
}

func TestConfirm_AfterRegister(t *testing.T) {
	t.Parallel()

	c := setup()
	ctx := c.NewContext()
	log := &bytes.Buffer{}
	c.LogWriter = log
	c.Mailer = authboss.LogMailer(log)
	c.PrimaryID = authboss.StoreUsername

	sentEmail := false

	goConfirmEmail = func(c *Confirm, ctx *authboss.Context, to, token string) {
		c.confirmEmail(ctx, to, token)
		sentEmail = true
	}

	if err := c.afterRegister(ctx); err != errUserMissing {
		t.Error("Expected it to die with user error:", err)
	}

	ctx.User = authboss.Attributes{c.PrimaryID: "username"}
	if err := c.afterRegister(ctx); err == nil || err.(authboss.AttributeErr).Name != "email" {
		t.Error("Expected it to die with e-mail address error:", err)
	}

	ctx.User[authboss.StoreEmail] = "a@a.com"
	log.Reset()
	c.afterRegister(ctx)
	if str := log.String(); !strings.Contains(str, "Subject: Confirm New Account") {
		t.Error("Expected it to send an e-mail:", str)
	}

	if !sentEmail {
		t.Error("Expected it to send an e-mail.")
	}
}

func TestConfirm_ConfirmHandlerErrors(t *testing.T) {
	t.Parallel()

	c := setup()
	log := &bytes.Buffer{}
	c.LogWriter = log
	c.Mailer = authboss.LogMailer(log)

	tests := []struct {
		URL       string
		Confirmed bool
		Error     error
	}{
		{"http://localhost", false, authboss.ClientDataErr{Name: FormValueConfirm}},
		{"http://localhost?cnf=c$ats", false,
			authboss.ErrAndRedirect{Location: "/", Err: errors.New("confirm: token failed to decode \"c$ats\" => illegal base64 data at input byte 1\n")},
		},
		{"http://localhost?cnf=SGVsbG8sIHBsYXlncm91bmQ=", false,
			authboss.ErrAndRedirect{Location: "/", Err: errors.New(`confirm: token not found`)},
		},
	}

	for i, test := range tests {
		r, _ := http.NewRequest("GET", test.URL, nil)
		w := httptest.NewRecorder()
		ctx := c.NewContext()

		err := c.confirmHandler(ctx, w, r)
		if err == nil {
			t.Fatalf("%d) Expected an error", i)
		}

		if !reflect.DeepEqual(err, test.Error) {
			t.Errorf("Expected: %v, got: %v", test.Error, err)
		}

		is, ok := ctx.User.Bool(StoreConfirmed)
		if ok && is {
			t.Error("The user should not be confirmed.")
		}
	}
}

func TestConfirm_Confirm(t *testing.T) {
	t.Parallel()

	c := setup()
	ctx := c.NewContext()
	log := &bytes.Buffer{}
	c.LogWriter = log
	c.PrimaryID = authboss.StoreUsername
	c.Mailer = authboss.LogMailer(log)

	// Create a token
	token := []byte("hi")
	sum := md5.Sum(token)

	// Create the "database"
	storer := mocks.NewMockStorer()
	c.Storer = storer
	user := authboss.Attributes{
		authboss.StoreUsername: "usern",
		StoreConfirmToken:      base64.StdEncoding.EncodeToString(sum[:]),
	}
	storer.Users["usern"] = user

	// Make a request with session and context support.
	r, _ := http.NewRequest("GET", "http://localhost?cnf="+base64.URLEncoding.EncodeToString(token), nil)
	w := httptest.NewRecorder()
	ctx = c.NewContext()
	ctx.CookieStorer = mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer()
	ctx.User = user
	ctx.SessionStorer = session

	c.confirmHandler(ctx, w, r)
	if w.Code != http.StatusFound {
		t.Error("Expected a redirect after success:", w.Code)
	}

	if log.Len() != 0 {
		t.Error("Expected a clean log on success:", log.String())
	}

	is, ok := ctx.User.Bool(StoreConfirmed)
	if !ok || !is {
		t.Error("The user should be confirmed.")
	}

	tok, ok := ctx.User.String(StoreConfirmToken)
	if ok && len(tok) != 0 {
		t.Error("Confirm token should have been wiped out.")
	}

	if key, ok := ctx.SessionStorer.Get(authboss.SessionKey); !ok || len(key) == 0 {
		t.Error("Should have logged the user in.")
	}
	if success, ok := ctx.SessionStorer.Get(authboss.FlashSuccessKey); !ok || len(success) == 0 {
		t.Error("Should have left a nice message.")
	}
}
*/
