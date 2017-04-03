package recover

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/authboss.v1"
	"gopkg.in/authboss.v1/internal/mocks"
)

const (
	testURLBase64Token = "MTIzNA=="
	testStdBase64Token = "gdyb21LQTcIANtvYMT7QVQ=="
)

func testSetup() (r *Recover, s *mocks.MockStorer, l *bytes.Buffer) {
	s = mocks.NewMockStorer()
	l = &bytes.Buffer{}

	ab := authboss.New()
	ab.Layout = template.Must(template.New("").Parse(`{{template "authboss" .}}`))
	ab.LayoutHTMLEmail = template.Must(template.New("").Parse(`<strong>{{template "authboss" .}}</strong>`))
	ab.LayoutTextEmail = template.Must(template.New("").Parse(`{{template "authboss" .}}`))
	ab.Storer = s
	ab.XSRFName = "xsrf"
	ab.XSRFMaker = func(_ http.ResponseWriter, _ *http.Request) string {
		return "xsrfvalue"
	}
	ab.PrimaryID = authboss.StoreUsername
	ab.LogWriter = l

	ab.Policies = []authboss.Validator{
		authboss.Rules{
			FieldName:       "username",
			Required:        true,
			MinLength:       2,
			MaxLength:       4,
			AllowWhitespace: false,
		},
		authboss.Rules{
			FieldName:       "password",
			Required:        true,
			MinLength:       4,
			MaxLength:       8,
			AllowWhitespace: false,
		},
	}

	r = &Recover{}
	if err := r.Initialize(ab); err != nil {
		panic(err)
	}

	return r, s, l
}

func testRequest(ab *authboss.Authboss, method string, postFormValues ...string) (*authboss.Context, *httptest.ResponseRecorder, *http.Request, authboss.ClientStorerErr) {
	sessionStorer := mocks.NewMockClientStorer()
	ctx := ab.NewContext()
	r := mocks.MockRequest(method, postFormValues...)
	ctx.SessionStorer = sessionStorer

	return ctx, httptest.NewRecorder(), r, sessionStorer
}

func TestRecover(t *testing.T) {
	t.Parallel()

	r, _, _ := testSetup()

	storage := r.Storage()
	if storage[r.PrimaryID] != authboss.String {
		t.Error("Expected storage KV:", r.PrimaryID, authboss.String)
	}
	if storage[authboss.StoreEmail] != authboss.String {
		t.Error("Expected storage KV:", authboss.StoreEmail, authboss.String)
	}
	if storage[authboss.StorePassword] != authboss.String {
		t.Error("Expected storage KV:", authboss.StorePassword, authboss.String)
	}
	if storage[StoreRecoverToken] != authboss.String {
		t.Error("Expected storage KV:", StoreRecoverToken, authboss.String)
	}
	if storage[StoreRecoverTokenExpiry] != authboss.String {
		t.Error("Expected storage KV:", StoreRecoverTokenExpiry, authboss.String)
	}

	routes := r.Routes()
	if routes["/recover"] == nil {
		t.Error("Expected route '/recover' with handleFunc")
	}
	if routes["/recover/complete"] == nil {
		t.Error("Expected route '/recover/complete' with handleFunc")
	}
}

func TestRecover_startHandlerFunc_GET(t *testing.T) {
	t.Parallel()

	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest(rec.Authboss, "GET")

	if err := rec.startHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `<form action="recover"`) {
		t.Error("Should have rendered a form")
	}
	if !strings.Contains(body, `name="`+rec.PrimaryID) {
		t.Error("Form should contain the primary ID field")
	}
	if !strings.Contains(body, `name="confirm_`+rec.PrimaryID) {
		t.Error("Form should contain the confirm primary ID field")
	}
}

func TestRecover_startHandlerFunc_POST_ValidationFails(t *testing.T) {
	t.Parallel()

	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest(rec.Authboss, "POST")

	if err := rec.startHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	if !strings.Contains(w.Body.String(), "Cannot be blank") {
		t.Error("Expected error about email being blank")
	}
}

func TestRecover_startHandlerFunc_POST_UserNotFound(t *testing.T) {
	t.Parallel()

	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest(rec.Authboss, "POST", "username", "john", "confirm_username", "john")

	err := rec.startHandlerFunc(ctx, w, r)
	if err == nil {
		t.Error("Expected error:", err)
	}
	rerr, ok := err.(authboss.ErrAndRedirect)
	if !ok {
		t.Error("Expected ErrAndRedirect error")
	}

	if rerr.Location != rec.RecoverOKPath {
		t.Error("Unexpected location:", rerr.Location)
	}

	if rerr.FlashSuccess != recoverInitiateSuccessFlash {
		t.Error("Unexpected success flash", rerr.FlashSuccess)
	}
}

func TestRecover_startHandlerFunc_POST(t *testing.T) {
	t.Parallel()

	rec, storer, _ := testSetup()

	storer.Users["john"] = authboss.Attributes{authboss.StoreUsername: "john", authboss.StoreEmail: "a@b.c"}

	sentEmail := false
	goRecoverEmail = func(_ *Recover, _ *authboss.Context, _, _ string) {
		sentEmail = true
	}

	ctx, w, r, sessionStorer := testRequest(rec.Authboss, "POST", "username", "john", "confirm_username", "john")

	if err := rec.startHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if !sentEmail {
		t.Error("Expected email to have been sent")
	}

	if val, err := storer.Users["john"].StringErr(StoreRecoverToken); err != nil {
		t.Error("Unexpected error:", err)
	} else if len(val) <= 0 {
		t.Error("Unexpected Recover Token to be set")
	}

	if val, err := storer.Users["john"].DateTimeErr(StoreRecoverTokenExpiry); err != nil {
		t.Error("Unexpected error:", err)
	} else if !val.After(time.Now()) {
		t.Error("Expected recovery token expiry to be greater than now")
	}

	if w.Code != http.StatusFound {
		t.Error("Unexpected status:", w.Code)
	}

	loc := w.Header().Get("Location")
	if loc != rec.RecoverOKPath {
		t.Error("Unexpected location:", loc)
	}

	if value, ok := sessionStorer.Get(authboss.FlashSuccessKey); !ok {
		t.Error("Expected success flash message")
	} else if value != recoverInitiateSuccessFlash {
		t.Error("Unexpected success flash message")
	}
}

func TestRecover_startHandlerFunc_OtherMethods(t *testing.T) {
	t.Parallel()

	rec, _, _ := testSetup()

	methods := []string{"HEAD", "PUT", "DELETE", "TRACE", "CONNECT"}

	for i, method := range methods {
		_, w, r, _ := testRequest(rec.Authboss, method)

		if err := rec.startHandlerFunc(nil, w, r); err != nil {
			t.Errorf("%d> Unexpected error: %s", i, err)
		}

		if http.StatusMethodNotAllowed != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, http.StatusMethodNotAllowed, w.Code)
			continue
		}
	}
}

func TestRecover_newToken(t *testing.T) {
	t.Parallel()

	regexURL := regexp.MustCompile(`^(?:[A-Za-z0-9-_]{4})*(?:[A-Za-z0-9-_]{2}==|[A-Za-z0-9-_]{3}=)?$`)
	regexSTD := regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)

	encodedToken, encodedSum, _ := newToken()

	if !regexURL.MatchString(encodedToken) {
		t.Error("Expected encodedToken to be base64 encoded")
	}

	if !regexSTD.MatchString(encodedSum) {
		t.Error("Expected encodedSum to be base64 encoded")
	}
}

func TestRecover_sendRecoverMail_FailToSend(t *testing.T) {
	t.Parallel()

	r, _, logger := testSetup()

	mailer := mocks.NewMockMailer()
	mailer.SendErr = "failed to send"
	r.Mailer = mailer

	r.sendRecoverEmail(r.NewContext(), "", "")

	if !strings.Contains(logger.String(), "failed to send") {
		t.Error("Expected logged to have msg:", "failed to send")
	}
}

func TestRecover_sendRecoverEmail(t *testing.T) {
	t.Parallel()

	r, _, _ := testSetup()

	mailer := mocks.NewMockMailer()
	r.EmailSubjectPrefix = "foo "
	r.RootURL = "bar"
	r.Mailer = mailer

	r.sendRecoverEmail(r.NewContext(), "a@b.c", "abc=")
	if len(mailer.Last.To) != 1 {
		t.Error("Expected 1 to email")
	}
	if mailer.Last.To[0] != "a@b.c" {
		t.Error("Unexpected to email:", mailer.Last.To[0])
	}
	if mailer.Last.Subject != "foo Password Reset" {
		t.Error("Unexpected subject:", mailer.Last.Subject)
	}

	url := fmt.Sprintf("%s/recover/complete?token=abc%%3D", r.RootURL)
	if !strings.Contains(mailer.Last.HTMLBody, url) {
		t.Error("Expected HTMLBody to contain url:", url)
	}
	if !strings.Contains(mailer.Last.TextBody, url) {
		t.Error("Expected TextBody to contain url:", url)
	}
}

func TestRecover_completeHandlerFunc_GET_VerifyFails(t *testing.T) {
	t.Parallel()

	rec, storer, _ := testSetup()

	ctx, w, r, _ := testRequest(rec.Authboss, "GET", "token", testURLBase64Token)

	err := rec.completeHandlerFunc(ctx, w, r)
	rerr, ok := err.(authboss.ErrAndRedirect)
	if !ok {
		t.Error("Expected ErrAndRedirect:", err)
	}
	if rerr.Location != "/" {
		t.Error("Unexpected location:", rerr.Location)
	}

	var zeroTime time.Time
	storer.Users["john"] = authboss.Attributes{StoreRecoverToken: testStdBase64Token, StoreRecoverTokenExpiry: zeroTime}

	ctx, w, r, _ = testRequest(rec.Authboss, "GET", "token", testURLBase64Token)

	err = rec.completeHandlerFunc(ctx, w, r)
	rerr, ok = err.(authboss.ErrAndRedirect)
	if !ok {
		t.Error("Expected ErrAndRedirect")
	}
	if rerr.Location != "/recover" {
		t.Error("Unexpected location:", rerr.Location)
	}
	if rerr.FlashError != recoverTokenExpiredFlash {
		t.Error("Unexpcted flash error:", rerr.FlashError)
	}
}

func TestRecover_completeHandlerFunc_GET(t *testing.T) {
	t.Parallel()

	rec, storer, _ := testSetup()

	storer.Users["john"] = authboss.Attributes{StoreRecoverToken: testStdBase64Token, StoreRecoverTokenExpiry: time.Now().Add(1 * time.Hour)}

	ctx, w, r, _ := testRequest(rec.Authboss, "GET", "token", testURLBase64Token)

	if err := rec.completeHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `<form action="recover/complete"`) {
		t.Error("Should have rendered a form")
	}
	if !strings.Contains(body, `name="password"`) {
		t.Error("Form should contain the password field")
	}
	if !strings.Contains(body, `name="confirm_password"`) {
		t.Error("Form should contain the confirm password field")
	}
	if !strings.Contains(body, `name="token"`) {
		t.Error("Form should contain the token field")
	}
}

func TestRecover_completeHandlerFunc_POST_TokenMissing(t *testing.T) {
	t.Parallel()

	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest(rec.Authboss, "POST")

	err := rec.completeHandlerFunc(ctx, w, r)
	if err == nil || err.Error() != "Failed to retrieve client attribute: token" {
		t.Error("Unexpected error:", err)
	}

}

func TestRecover_completeHandlerFunc_POST_ValidationFails(t *testing.T) {
	t.Parallel()

	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest(rec.Authboss, "POST", "token", testURLBase64Token)

	if err := rec.completeHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	if !strings.Contains(w.Body.String(), "Cannot be blank") {
		t.Error("Expected error about password being blank")
	}
}

func TestRecover_completeHandlerFunc_POST_VerificationFails(t *testing.T) {
	t.Parallel()

	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest(rec.Authboss, "POST", "token", testURLBase64Token, authboss.StorePassword, "abcd", "confirm_"+authboss.StorePassword, "abcd")

	if err := rec.completeHandlerFunc(ctx, w, r); err == nil {
		log.Println(w.Body.String())
		t.Error("Expected error")
	}
}

func TestRecover_completeHandlerFunc_POST(t *testing.T) {
	t.Parallel()

	rec, storer, _ := testSetup()

	storer.Users["john"] = authboss.Attributes{rec.PrimaryID: "john", StoreRecoverToken: testStdBase64Token, StoreRecoverTokenExpiry: time.Now().Add(1 * time.Hour), authboss.StorePassword: "asdf"}

	cbCalled := false

	rec.Callbacks = authboss.NewCallbacks()
	rec.Callbacks.After(authboss.EventPasswordReset, func(_ *authboss.Context) error {
		cbCalled = true
		return nil
	})

	rec.Authboss.AllowLoginAfterResetPassword = false

	ctx, w, r, sessionStorer := testRequest(rec.Authboss, "POST", "token", testURLBase64Token, authboss.StorePassword, "abcd", "confirm_"+authboss.StorePassword, "abcd")

	if err := rec.completeHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	var zeroTime time.Time

	u := storer.Users["john"]
	if password, ok := u.String(authboss.StorePassword); !ok || password == "asdf" {
		t.Error("Expected password to have been reset")
	}

	if recToken, ok := u.String(StoreRecoverToken); !ok || recToken != "" {
		t.Error("Expected recovery token to have been zeroed")
	}

	if reCExpiry, ok := u.DateTime(StoreRecoverTokenExpiry); !ok || !reCExpiry.Equal(zeroTime) {
		t.Error("Expected recovery token expiry to have been zeroed")
	}

	if !cbCalled {
		t.Error("Expected EventPasswordReset callback to have been fired")
	}

	if _, ok := sessionStorer.Get(authboss.SessionKey); ok {
		t.Error("Should not have logged the user in since AllowInsecureLoginAfterConfirm is false.")
	}

	if w.Code != http.StatusFound {
		t.Error("Unexpected status:", w.Code)
	}

	loc := w.Header().Get("Location")
	if loc != rec.AuthLogoutOKPath {
		t.Error("Unexpected location:", loc)
	}
}

func Test_verifyToken_MissingToken(t *testing.T) {
	t.Parallel()

	testSetup()
	r := mocks.MockRequest("GET")

	if _, err := verifyToken(nil, r); err == nil {
		t.Error("Expected error about missing token")
	}
}

func Test_verifyToken_InvalidToken(t *testing.T) {
	t.Parallel()

	rec, storer, _ := testSetup()
	storer.Users["a"] = authboss.Attributes{
		StoreRecoverToken: testStdBase64Token,
	}

	ctx := rec.Authboss.NewContext()
	req, _ := http.NewRequest("GET", "/?token=asdf", nil)
	if _, err := verifyToken(ctx, req); err != authboss.ErrUserNotFound {
		t.Error("Unexpected error:", err)
	}
}

func Test_verifyToken_ExpiredToken(t *testing.T) {
	t.Parallel()

	rec, storer, _ := testSetup()
	storer.Users["a"] = authboss.Attributes{
		StoreRecoverToken:       testStdBase64Token,
		StoreRecoverTokenExpiry: time.Now().Add(time.Duration(-24) * time.Hour),
	}

	ctx := rec.Authboss.NewContext()
	req, _ := http.NewRequest("GET", "/?token="+testURLBase64Token, nil)
	if _, err := verifyToken(ctx, req); err != errRecoveryTokenExpired {
		t.Error("Unexpected error:", err)
	}
}

func Test_verifyToken(t *testing.T) {
	t.Parallel()

	rec, storer, _ := testSetup()
	storer.Users["a"] = authboss.Attributes{
		StoreRecoverToken:       testStdBase64Token,
		StoreRecoverTokenExpiry: time.Now().Add(time.Duration(24) * time.Hour),
	}

	ctx := rec.Authboss.NewContext()
	req, _ := http.NewRequest("GET", "/?token="+testURLBase64Token, nil)
	attrs, err := verifyToken(ctx, req)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if attrs == nil {
		t.Error("Unexpected nil attrs")
	}
}
