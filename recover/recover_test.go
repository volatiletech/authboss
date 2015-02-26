package recover

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

const (
	testUrlBase64Token = "MTIzNA=="
	testStdBase64Token = "gdyb21LQTcIANtvYMT7QVQ=="
)

func testSetup() (r *Recover, s *mocks.MockStorer, l *bytes.Buffer) {
	s = mocks.NewMockStorer()
	l = &bytes.Buffer{}

	authboss.Cfg = authboss.NewConfig()
	authboss.Cfg.Layout = template.Must(template.New("").Parse(`{{template "authboss" .}}`))
	authboss.Cfg.LayoutEmail = template.Must(template.New("").Parse(`{{template "authboss" .}}`))
	authboss.Cfg.Storer = s
	authboss.Cfg.XSRFName = "xsrf"
	authboss.Cfg.XSRFMaker = func(_ http.ResponseWriter, _ *http.Request) string {
		return "xsrfvalue"
	}
	authboss.Cfg.PrimaryID = authboss.StoreUsername
	authboss.Cfg.LogWriter = l

	r = &Recover{}
	if err := r.Initialize(); err != nil {
		panic(err)
	}

	return r, s, l
}

func testRequest(method string, postFormValues ...string) (*authboss.Context, *httptest.ResponseRecorder, *http.Request, authboss.ClientStorerErr) {
	r, err := http.NewRequest(method, "", nil)
	if err != nil {
		panic(err)
	}

	sessionStorer := mocks.NewMockClientStorer()
	ctx := mocks.MockRequestContext(postFormValues...)
	ctx.SessionStorer = sessionStorer

	return ctx, httptest.NewRecorder(), r, sessionStorer
}

func TestRecover(t *testing.T) {
	r, _, _ := testSetup()

	storage := r.Storage()
	if storage[authboss.Cfg.PrimaryID] != authboss.String {
		t.Error("Expected storage KV:", authboss.Cfg.PrimaryID, authboss.String)
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
	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest("GET")

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
	if !strings.Contains(body, `name="`+authboss.Cfg.PrimaryID) {
		t.Error("Form should contain the primary ID field")
	}
	if !strings.Contains(body, `name="confirm_`+authboss.Cfg.PrimaryID) {
		t.Error("Form should contain the confirm primary ID field")
	}
}

func TestRecover_startHandlerFunc_POST_ValidationFails(t *testing.T) {
	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest("POST")

	if err := rec.startHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	if !strings.Contains(w.Body.String(), "Cannot be blank") {
		t.Error("Expected error about username being blank")
	}
}

func TestRecover_startHandlerFunc_POST_UserNotFound(t *testing.T) {
	rec, _, _ := testSetup()
	ctx, w, r, _ := testRequest("POST", "username", "john", "confirm_username", "john")

	err := rec.startHandlerFunc(ctx, w, r)
	if err == nil {
		t.Error("Expected error:", err)
	}
	rerr, ok := err.(authboss.ErrAndRedirect)
	if !ok {
		t.Error("Expected ErrAndRedirect error")
	}

	if rerr.Location != authboss.Cfg.RecoverOKPath {
		t.Error("Unexpected location:", rerr.Location)
	}

	if rerr.FlashSuccess != recoverInitiateSuccessFlash {
		t.Error("Unexpected success flash", rerr.FlashSuccess)
	}
}

func TestRecover_startHandlerFunc_POST(t *testing.T) {
	rec, storer, _ := testSetup()

	storer.Users["john"] = authboss.Attributes{authboss.StoreUsername: "john", authboss.StoreEmail: "a@b.c"}

	sentEmail := false
	goRecoverEmail = func(_ *Recover, _, _ string) {
		sentEmail = true
	}

	ctx, w, r, sessionStorer := testRequest("POST", "username", "john", "confirm_username", "john")

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
	if loc != authboss.Cfg.RecoverOKPath {
		t.Error("Unexpected location:", loc)
	}

	if value, ok := sessionStorer.Get(authboss.FlashSuccessKey); !ok {
		t.Error("Expected success flash message")
	} else if value != recoverInitiateSuccessFlash {
		t.Error("Unexpected success flash message")
	}
}

func TestRecover_startHandlerFunc_OtherMethods(t *testing.T) {
	rec, _, _ := testSetup()

	methods := []string{"HEAD", "PUT", "DELETE", "TRACE", "CONNECT"}

	for i, method := range methods {
		_, w, r, _ := testRequest(method)

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
	a, _, logger := testSetup()

	mailer := mocks.NewMockMailer()
	mailer.SendErr = "failed to send"
	authboss.Cfg.Mailer = mailer

	a.sendRecoverEmail("", "")

	if !strings.Contains(logger.String(), "failed to send") {
		t.Error("Expected logged to have msg:", "failed to send")
	}
}

func TestRecover_sendRecoverEmail(t *testing.T) {
	a, _, _ := testSetup()

	mailer := mocks.NewMockMailer()
	authboss.Cfg.EmailSubjectPrefix = "foo "
	authboss.Cfg.HostName = "bar"
	authboss.Cfg.Mailer = mailer

	a.sendRecoverEmail("a@b.c", "abc=")
	if len(mailer.Last.To) != 1 {
		t.Error("Expected 1 to email")
	}
	if mailer.Last.To[0] != "a@b.c" {
		t.Error("Unexpected to email:", mailer.Last.To[0])
	}
	if mailer.Last.Subject != "foo Password Reset" {
		t.Error("Unexpected subject:", mailer.Last.Subject)
	}

	url := fmt.Sprintf("%s/recover/complete?token=abc=", authboss.Cfg.HostName)
	if !strings.Contains(mailer.Last.HTMLBody, url) {
		t.Error("Expected HTMLBody to contain url:", url)
	}
	if !strings.Contains(mailer.Last.TextBody, url) {
		t.Error("Expected TextBody to contain url:", url)
	}
}

func TestRecover_completeHandlerFunc_GET(t *testing.T) {

}

func TestRecover_completeHanlderFunc_POST(t *testing.T) {

}

func Test_verifyToken_MissingToken(t *testing.T) {
	testSetup()

	ctx := &authboss.Context{}
	if _, err := verifyToken(ctx); err == nil {
		t.Error("Expected error about missing token")
	}
}

func Test_verifyToken_InvalidToken(t *testing.T) {
	_, storer, _ := testSetup()
	storer.Users["a"] = authboss.Attributes{
		StoreRecoverToken: testStdBase64Token,
	}

	ctx := mocks.MockRequestContext("token", "asdf")
	if _, err := verifyToken(ctx); err != authboss.ErrUserNotFound {
		t.Error("Unexpected error:", err)
	}
}

func Test_verifyToken_ExpiredToken(t *testing.T) {
	_, storer, _ := testSetup()
	storer.Users["a"] = authboss.Attributes{
		StoreRecoverToken:       testStdBase64Token,
		StoreRecoverTokenExpiry: time.Now().Add(time.Duration(-24) * time.Hour),
	}

	ctx := mocks.MockRequestContext("token", testUrlBase64Token)
	if _, err := verifyToken(ctx); err != errRecoveryTokenExpired {
		t.Error("Unexpected error:", err)
	}
}

func Test_verifyToken(t *testing.T) {
	_, storer, _ := testSetup()
	storer.Users["a"] = authboss.Attributes{
		StoreRecoverToken:       testStdBase64Token,
		StoreRecoverTokenExpiry: time.Now().Add(time.Duration(24) * time.Hour),
	}

	ctx := mocks.MockRequestContext("token", testUrlBase64Token)
	attrs, err := verifyToken(ctx)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if attrs == nil {
		t.Error("Unexpected nil attrs")
	}
}
