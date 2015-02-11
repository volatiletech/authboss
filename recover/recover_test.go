package recover

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
	"gopkg.in/authboss.v0/internal/views"
)

type failStorer int

func (_ failStorer) Create(_ string, _ authboss.Attributes) error                { return nil }
func (_ failStorer) Put(_ string, _ authboss.Attributes) error                   { return nil }
func (_ failStorer) Get(_ string, _ authboss.AttributeMeta) (interface{}, error) { return nil, nil }

func Test_Initialize(t *testing.T) {
	t.Parallel()

	config := &authboss.Config{ViewsPath: os.TempDir()}
	m := &RecoverModule{}

	if err := m.Initialize(config); err == nil {
		t.Error("Expected error")
	} else if err.Error() != "recover: Need a RecoverStorer." {
		t.Error("Got error but wrong reason:", err)
	}
	config.Storer = new(failStorer)

	if err := m.Initialize(config); err == nil {
		t.Error("Expected error")
	} else if err.Error() != "recover: RecoverStorer required for recover functionality." {
		t.Error("Got error but wrong reason:", err)
	}
	config.Storer = mocks.NewMockStorer()

	if err := m.Initialize(config); err == nil {
		t.Error("Expected error")
	} else if err.Error() != "recover: Layout required for Recover functionallity." {
		t.Error("Got error but wrong reason:", err)
	}

	var err error
	config.Layout, err = template.New("").Parse(`{{template "authboss" .}}`)
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if err := m.Initialize(config); err == nil {
		t.Error("Expected error:", err)
	} else if err.Error() != "recover: LayoutEmail required for Recover functionallity." {
		t.Error("Got error but wrong reason:", err)
	}
	config.LayoutEmail, err = template.New("").Parse(`{{template "authboss" .}}`)

	if err != nil {
		t.Fatal("Unexpected error:", err)
	}

	if err := m.Initialize(config); err != nil {
		t.Error("Unexpected error:", err)
	}
}

func testValidTestConfig() *authboss.Config {
	config := &authboss.Config{}

	config.Storer = mocks.NewMockStorer()
	config.EmailFrom = "auth@boss.com"

	var err error
	if config.Layout, err = views.AssetToTemplate("layout.tpl"); err != nil {
		panic(err)
	}
	if config.LayoutEmail, err = views.AssetToTemplate("layoutEmail.tpl"); err != nil {
		panic(err)
	}

	config.RecoverRedirect = "/login"
	config.RecoverInitiateSuccessFlash = "sf"
	config.RecoverTokenExpiredFlash = "exf"
	config.RecoverFailedErrorFlash = "errf"

	config.Policies = []authboss.Validator{
		authboss.Rules{
			FieldName: "username",
			Required:  true,
		},
		authboss.Rules{
			FieldName: "password",
			Required:  true,
		},
	}
	config.ConfirmFields = []string{"username", "confirmUsername", "password", "confirmPassword"}
	config.LogWriter = &bytes.Buffer{}
	config.Mailer = &mocks.MockMailer{}
	config.EmailFrom = "auth@boss.com"
	config.HostName = "localhost"
	config.RecoverTokenDuration = time.Duration(24) * time.Hour
	config.BCryptCost = 4
	config.AuthLoginSuccessRoute = "/login"

	return config
}

func testValidRecoverModule() (*RecoverModule, *bytes.Buffer) {
	c := testValidTestConfig()

	m := &RecoverModule{}
	if err := m.Initialize(c); err != nil {
		panic(err)
	}

	return m, c.LogWriter.(*bytes.Buffer)
}

func Test_Routes(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()

	routes := m.Routes()

	if _, ok := routes["recover"]; !ok {
		t.Error("Expected route: recover")
	}

	if _, ok := routes["recover/complete"]; !ok {
		t.Error("Expected route: recover/complete")
	}
}

func Test_Storage(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()

	tests := []struct {
		Attr string
		Kind authboss.DataType
	}{
		{attrUsername, authboss.String},
		{attrRecoverToken, authboss.String},
		{attrEmail, authboss.String},
		{attrRecoverTokenExpiry, authboss.String},
		{attrPassword, authboss.String},
	}

	options := m.Storage()

	for i, test := range tests {
		if kind, ok := options[test.Attr]; !ok {
			t.Errorf("%s> Expected attr: %s", i, test.Attr)
		} else if kind != test.Kind {
			t.Errorf("%s> Expected DataType: %s", i, test.Kind)
		}
	}
}

func testHttpRequest(method, url string, data url.Values) (*httptest.ResponseRecorder, *http.Request, *authboss.Context) {
	var body io.Reader
	if method != "GET" {
		body = strings.NewReader(data.Encode())
	}

	r, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	ctx, err := authboss.ContextFromRequest(r)
	if err != nil {
		panic(err)
	}
	ctx.SessionStorer = mocks.MockClientStorer{}

	return w, r, ctx
}

func Test_recoverHandlerFunc_GET(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	w, r, ctx := testHttpRequest("GET", "/recover", nil)

	m.recoverHandlerFunc(ctx, w, r)

	expectedBody := &bytes.Buffer{}
	if err := m.templates[tplRecover].Execute(expectedBody, pageRecover{}); err != nil {
		panic(err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected code:", w.Code)
	}
	if !bytes.Equal(expectedBody.Bytes(), w.Body.Bytes()) {
		t.Error("Unexpected body:", w.Body.String())
	}
}

func Test_recoverHandlerFunc_POST_RecoveryFailed(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	w, r, ctx := testHttpRequest("POST", "/login", url.Values{"username": []string{"a"}, "confirmUsername": []string{"a"}})

	tpl := m.templates[tplRecover]
	expectedBody := &bytes.Buffer{}
	if err := tpl.Execute(expectedBody, pageRecover{
		Username:        "a",
		ConfirmUsername: "a",
		FlashError:      m.config.RecoverFailedErrorFlash,
	}); err != nil {
		panic(err)
	}

	// missing storer will cause this to fail
	m.recoverHandlerFunc(ctx, w, r)

	if w.Code != http.StatusOK {
		t.Error("Unexpected code:", w.Code)
	}

	if !bytes.Equal(expectedBody.Bytes(), w.Body.Bytes()) {
		t.Error("Unexpected body:", w.Body.String())
	}
}

func Test_recoverHandlerFunc_POST(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	w, r, ctx := testHttpRequest("POST", "/login", url.Values{"username": []string{"a"}, "confirmUsername": []string{"a"}})

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{"username": "", "password": "", "email": "a@b.c"}

	m.recoverHandlerFunc(ctx, w, r)

	if w.Code != http.StatusFound {
		t.Error("Unexpected code:", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/login" {
		t.Error("Unexpected redirect:", location)
	}

	successFlash := ctx.SessionStorer.(mocks.MockClientStorer)[authboss.FlashSuccessKey]
	if successFlash != m.config.RecoverInitiateSuccessFlash {
		t.Error("Unexpected success flash message:", successFlash)
	}
}

func Test_execTpl_TemplateExectionFail(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()
	w := httptest.NewRecorder()

	failTpl, err := template.New("").Parse("{{.Fail}}")
	if err != nil {
		panic("Failed to build tpl")
	}
	m.templates["fail.tpl"] = failTpl

	m.execTpl("fail.tpl", w, pageRecover{})

	if w.Code != http.StatusInternalServerError {
		t.Error("Unexpected code:", w.Code)
	}

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(actualLog, []byte("recover [unable to execute template]:")) {
		t.Error("Expected log message starting with:", "recover [unable to execute template]:")
	}
}

func Test_execTpl(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	w := httptest.NewRecorder()

	page := pageRecover{"bobby", "bob", nil, "", m.config.RecoverFailedErrorFlash}
	m.execTpl(tplRecover, w, page)

	tpl := m.templates[tplRecover]
	expectedBody := &bytes.Buffer{}
	if err := tpl.Execute(expectedBody, page); err != nil {
		panic(err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected code:", w.Code)
	}
	if !bytes.Equal(expectedBody.Bytes(), w.Body.Bytes()) {
		t.Error("Unexpected body:", w.Body.String())
	}
}

func Test_recover_UsernameValidationFail(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()
	ctx := mocks.MockRequestContext()

	page, emailSent := m.recover(ctx)
	if len(page.ErrMap["username"]) != 1 {
		t.Error("Exepted single validation error for username")
	}
	if page.ErrMap["username"][0] != "Cannot be blank" {
		t.Error("Unexpected validation error for username:", page.ErrMap["username"][0])
	}
	expectedLog := []byte("recover [validation failed]: username: Cannot be blank\n")
	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(expectedLog, actualLog) {
		t.Errorf("Unexpected logs: %q", string(actualLog))
	}
	if emailSent != nil {
		t.Error("Unexpected sent email")
	}
}

func Test_recover_ConfirmUsernameCheckFail(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()
	ctx := mocks.MockRequestContext("username", "a", "confirmUsername", "b")

	page, emailSent := m.recover(ctx)
	if len(page.ErrMap["username"]) != 0 {
		t.Error("Exepted no validation errors for username")
	}
	if len(page.ErrMap["confirmUsername"]) != 1 {
		t.Error("Exepted single validation error for confirmUsername")
	}
	if page.ErrMap["confirmUsername"][0] != "Does not match username" {
		t.Error("Unexpected validation error for confirmUsername:", page.ErrMap["confirmUsername"][0])
	}
	expectedLog := []byte("recover [validation failed]: confirmUsername: Does not match username\n")
	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(expectedLog, actualLog) {
		t.Error("Unexpected logs:", string(actualLog))
	}
	if emailSent != nil {
		t.Error("Unexpected sent email")
	}
}

func Test_recover_InvalidUser(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()
	ctx := mocks.MockRequestContext("username", "a", "confirmUsername", "a")

	page, emailSent := m.recover(ctx)
	if page.ErrMap != nil {
		t.Error("Exepted no validation errors")
	}
	if page.FlashError != m.config.RecoverFailedErrorFlash {
		t.Error("Expected flash error:", m.config.RecoverFailedErrorFlash)
	}

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(actualLog, []byte("recover [failed to recover]:")) {
		t.Error("Expected log message starting with:", "recover [failed to recover]:")
	}
	if emailSent != nil {
		t.Error("Unexpected sent email")
	}
}

func Test_recover(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{"username": "", "password": "", "email": "a@b.c"}

	ctx := mocks.MockRequestContext("username", "a", "confirmUsername", "a")

	page, emailSent := m.recover(ctx)
	if page != nil {
		t.Error("Expected nil page")
	}
	if emailSent == nil {
		t.Error("Expected sent email")
	}
}

func Test_makeAndSendToken_MissingStorer(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	ctx := mocks.MockRequestContext()

	err, ch := m.makeAndSendToken(ctx, "a")
	if err == nil || err.Error() != authboss.ErrUserNotFound.Error() {
		t.Error("Expected error:", authboss.ErrUserNotFound)
	}
	if ch != nil {
		t.Error("Expected nil channel")
	}
}

func Test_makeAndSendToken_CheckEmail(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	ctx := mocks.MockRequestContext()

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{"username": "", "password": ""}

	// missing
	err, ch := m.makeAndSendToken(ctx, "a")
	expectedErr := fmt.Sprintf("email required: %v", attrEmail)
	if err == nil || err.Error() != expectedErr {
		t.Error("Expected error:", expectedErr)
	}
	if ch != nil {
		t.Error("Expected nil channel")
	}

	// empty
	storer.Users["a"] = authboss.Attributes{"username": "", "password": "", "email": ""}
	err, ch = m.makeAndSendToken(ctx, "a")
	if err == nil || err.Error() != expectedErr {
		t.Error("Expected error:", expectedErr)
	}
	if ch != nil {
		t.Error("Expected nil channel")
	}
}

func Test_makeAndSendToken(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	ctx := mocks.MockRequestContext()

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{"username": "a", "password": "b", "email": "a@b.c"}

	err, ch := m.makeAndSendToken(ctx, "a")

	_, ok = storer.Users["a"][attrRecoverToken]
	if !ok {
		t.Error("Expected recover token")
	}

	_, ok = storer.Users["a"][attrRecoverTokenExpiry]
	if !ok {
		t.Error("Expected recover token expiry")
	}

	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if ch == nil {
		t.Error("Unexpected nil channel")
	}
}

func Test_sendRecoverEmail_InvalidTemplates(t *testing.T) {
	t.Parallel()
	m, logger := testValidRecoverModule()

	failTpl, err := template.New("").Parse("{{.Fail}}")
	if err != nil {
		panic("Failed to build tpl")
	}

	// broken html template
	originalHtmlEmail := m.emailTemplates[tplInitHTMLEmail]
	m.emailTemplates[tplInitHTMLEmail] = failTpl

	<-m.sendRecoverEmail("a@b.c", []byte("abc123"))

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}

	if !bytes.Contains(actualLog, []byte("recover [failed to build html email]:")) {
		t.Error("Expected log message starting with:", "recover [failed to build html email]:")
	}

	// broken plain text template
	m.emailTemplates[tplInitHTMLEmail] = originalHtmlEmail
	m.emailTemplates[tplInitTextEmail] = failTpl

	<-m.sendRecoverEmail("a@b.c", []byte("abc123"))

	actualLog, err = ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}

	if !bytes.Contains(actualLog, []byte("recover [failed to build plaintext email]:")) {
		t.Error("Expected log message starting with:", "recover [failed to build plaintext email]:")
	}
}

type failMailer struct{}

func (_ failMailer) Send(_ authboss.Email) error {
	return errors.New("")
}

func Test_sendRecoverEmail_FailToSend(t *testing.T) {
	t.Parallel()
	m, logger := testValidRecoverModule()

	m.config.Mailer = failMailer{}
	<-m.sendRecoverEmail("a@b.c", []byte("abc123"))

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}

	if !bytes.Contains(actualLog, []byte("recover [failed to send email]:")) {
		t.Error("Expecte log message starting with:", "recover [failed to send email]:")
	}
}

func Test_sendRecoverEmail(t *testing.T) {
	t.Parallel()
	m, _ := testValidRecoverModule()

	<-m.sendRecoverEmail("a@b.c", []byte("abc123"))

	mailer, ok := m.config.Mailer.(*mocks.MockMailer)
	if !ok {
		panic("Failed to assert mock mailer")
	}

	sent := mailer.Last
	if len(sent.To) != 1 {
		t.Error("Expected one to email")
	}
	if sent.To[0] != "a@b.c" {
		t.Error("Unexpected to email:", sent.To[0])
	}

	if sent.From != m.config.EmailFrom {
		t.Error("Unexpected from email:", sent.From)
	}

	if sent.Subject != "Password Reset" {
		t.Error("Unexpected subject:", sent.Subject)
	}

	data := struct {
		Link string
	}{
		fmt.Sprintf("%s/recover/complete?token=%s",
			m.config.HostName,
			base64.URLEncoding.EncodeToString([]byte("abc123")),
		),
	}
	html, err := m.emailTemplates.ExecuteTemplate(tplInitHTMLEmail, data)
	if err != nil {
		panic(err)
	}
	test, err := m.emailTemplates.ExecuteTemplate(tplInitTextEmail, data)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(html.Bytes(), []byte(sent.HTMLBody)) {
		t.Error("Unexpected html body:", sent.HTMLBody)
	}
	if !bytes.Equal(test.Bytes(), []byte(sent.TextBody)) {
		t.Error("Unexpected text body:", sent.TextBody)
	}
}

func Test_recoverHandlerFunc_OtherMethods(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()

	for i, method := range []string{"HEAD", "PUT", "DELETE", "TRACE", "CONNECT"} {
		w, r, _ := testHttpRequest(method, "/recover", nil)

		m.recoverHandlerFunc(nil, w, r)

		if http.StatusMethodNotAllowed != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, http.StatusMethodNotAllowed, w.Code)
			continue
		}
	}
}

const (
	testUrlBase64Token = "MTIzNA=="
	testStdBase64Token = "gdyb21LQTcIANtvYMT7QVQ=="
)

func Test_recoverCompleteHandlerFunc_GET_TokenExpired(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["b"] = authboss.Attributes{
		attrUsername:           "b",
		attrRecoverToken:       testStdBase64Token,
		attrRecoverTokenExpiry: time.Now().Add(time.Duration(-24) * time.Hour),
	}

	w, r, ctx := testHttpRequest("GET", fmt.Sprintf("/recover/complete?token=%s", testUrlBase64Token), nil)
	clientStorer := mocks.MockClientStorer{}
	ctx.SessionStorer = clientStorer

	m.recoverCompleteHandlerFunc(ctx, w, r)

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(actualLog, []byte("recover [token expired]:")) {
		t.Error("Expected logs to start with:", "recover [token expired]:")
	}

	if flash := clientStorer[authboss.FlashErrorKey]; flash != m.config.RecoverTokenExpiredFlash {
		t.Error("Unexpected error flash:", flash)
	}

	if location := w.Header().Get("Location"); location != "/recover" {
		t.Error("Unexpected location:", location)
	}
}

func Test_recoverCompleteHandlerFunc_GET_OtherErrors(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()
	w, r, ctx := testHttpRequest("GET", "/recover/complete?token=asdf", nil)

	m.recoverCompleteHandlerFunc(ctx, w, r)

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(actualLog, []byte("recover:")) {
		t.Error("Expected logs to start with:", "recover:")
	}

	if location := w.Header().Get("Location"); location != "/" {
		t.Error("Unexpected location:", location)
	}
}

func Test_recoverCompleteHandlerFunc_GET(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["b"] = authboss.Attributes{
		attrUsername:           "b",
		attrRecoverToken:       testStdBase64Token,
		attrRecoverTokenExpiry: time.Now().Add(time.Duration(24) * time.Hour),
	}

	w, r, ctx := testHttpRequest("GET", fmt.Sprintf("/recover/complete?token=%s", testUrlBase64Token), nil)
	ctx.SessionStorer = mocks.MockClientStorer{authboss.FlashErrorKey: "asdf"}

	m.recoverCompleteHandlerFunc(ctx, w, r)

	page := pageRecoverComplete{Token: testUrlBase64Token, FlashError: "asdf"}
	expectedBody := &bytes.Buffer{}
	if err := m.templates[tplRecoverComplete].Execute(expectedBody, page); err != nil {
		panic(err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected code:", w.Code)
	}
	if !bytes.Equal(expectedBody.Bytes(), w.Body.Bytes()) {
		t.Error("Unexpected body:", w.Body.String())
	}
}

func Test_recoverCompleteHandlerFunc_POST_RecoveryCompleteFailed(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	w, r, ctx := testHttpRequest(
		"POST",
		fmt.Sprintf("/recover/complete?token=%s", testUrlBase64Token),
		url.Values{"password": []string{"a"}, "confirmPassword": []string{"a"}},
	)

	tpl := m.templates[tplRecoverComplete]
	expectedBody := &bytes.Buffer{}
	if err := tpl.Execute(expectedBody, pageRecoverComplete{
		Token:           testUrlBase64Token,
		Password:        "a",
		ConfirmPassword: "a",
		FlashError:      m.config.RecoverFailedErrorFlash,
	}); err != nil {
		panic(err)
	}

	// missing storer will cause this to fail
	m.recoverCompleteHandlerFunc(ctx, w, r)

	// spew.Dump(expectedBody.Bytes())
	// spew.Dump(w.Body.Bytes())

	if w.Code != http.StatusOK {
		t.Error("Unexpected code:", w.Code)
	}

	if !bytes.Equal(expectedBody.Bytes(), w.Body.Bytes()) {
		t.Error("Unexpected body:", w.Body.String())
	}
}

func Test_recoverCompleteHandlerFunc_POST(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()
	w, r, ctx := testHttpRequest(
		"POST",
		fmt.Sprintf("/recover/complete?token=%s", testUrlBase64Token),
		url.Values{"password": []string{"a"}, "confirmPassword": []string{"a"}},
	)

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{
		attrUsername:           "a",
		attrRecoverToken:       testStdBase64Token,
		attrRecoverTokenExpiry: time.Now().Add(time.Duration(24) * time.Hour),
	}

	m.recoverCompleteHandlerFunc(ctx, w, r)

	log.Println(logger)

	if w.Code != http.StatusFound {
		t.Error("Unexpected code:", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/login" {
		t.Error("Unexpected redirect:", location)
	}
}

func Test_verifyToken_MissingToken(t *testing.T) {
	t.Parallel()

	ctx := mocks.MockRequestContext()
	_, err := verifyToken(ctx, nil)

	if err.Error() != "missing form value: token" {
		t.Error("Unexpected error:", err)
	}
}

func Test_verifyToken_InvalidToken(t *testing.T) {
	t.Parallel()

	config := testValidTestConfig()
	storer, ok := config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{
		attrRecoverToken: testStdBase64Token,
	}

	ctx := mocks.MockRequestContext("token", "asdf")
	_, err := verifyToken(ctx, storer)

	if err.Error() != authboss.ErrUserNotFound.Error() {
		t.Error("Unexpected error:", err)
	}
}

func Test_verifyToken_ExpiredToken(t *testing.T) {
	t.Parallel()

	config := testValidTestConfig()
	storer, ok := config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{
		attrRecoverToken:       testStdBase64Token,
		attrRecoverTokenExpiry: time.Now().Add(time.Duration(-24) * time.Hour),
	}

	ctx := mocks.MockRequestContext("token", testUrlBase64Token)
	_, err := verifyToken(ctx, storer)

	if err.Error() != "recovery token expired" {
		t.Error("Unexpected error:", err)
	}
}

func Test_verifyToken(t *testing.T) {
	t.Parallel()
	config := testValidTestConfig()

	storer, ok := config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{
		attrRecoverToken:       testStdBase64Token,
		attrRecoverTokenExpiry: time.Now().Add(time.Duration(24) * time.Hour),
	}

	ctx := mocks.MockRequestContext("token", testUrlBase64Token)
	attrs, err := verifyToken(ctx, storer)

	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if attrs == nil {
		t.Error("Unexpected nil attrs")
	}
}

func Test_recoverComplete_TokenVerificationFails(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()
	ctx := mocks.MockRequestContext()

	errPage := m.recoverComplete(ctx)
	if errPage == nil {
		t.Error("Expected err page")
	}
	if !reflect.DeepEqual(*errPage, pageRecoverComplete{FlashError: m.config.RecoverFailedErrorFlash}) {
		t.Error("Unexpected err page:", errPage)
	}

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(actualLog, []byte("recover [failed to verify token]:")) {
		t.Error("Expected logs to start with:", "recover [failed to verify token]:")
	}
}

func Test_recoverComplete_ValidationFails(t *testing.T) {
	t.Parallel()

	m, logger := testValidRecoverModule()
	ctx := mocks.MockRequestContext("token", testUrlBase64Token, "password", "a", "confirmPassword", "b")

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["b"] = authboss.Attributes{
		attrRecoverToken:       testStdBase64Token,
		attrRecoverTokenExpiry: time.Now().Add(time.Duration(24) * time.Hour),
	}

	errPage := m.recoverComplete(ctx)
	if errPage == nil {
		t.Error("Expected err page")
	}
	expectedErrPage := pageRecoverComplete{
		Token:           testUrlBase64Token,
		Password:        "a",
		ConfirmPassword: "b",
		ErrMap:          map[string][]string{"confirmPassword": []string{"Does not match password"}},
	}

	if !reflect.DeepEqual(*errPage, expectedErrPage) {
		t.Error("Unexpected err page:", errPage)
	}

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	expetedLog := []byte("recover [validation failed]: confirmPassword: Does not match password\n")
	if !bytes.Equal(actualLog, expetedLog) {
		t.Error("Expected logs:", string(expetedLog))
	}
}

func Test_recoverComplete(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()
	ctx := mocks.MockRequestContext("token", testUrlBase64Token, "password", "a", "confirmPassword", "a")

	clientStorer := mocks.MockClientStorer{}
	ctx.SessionStorer = clientStorer

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["b"] = authboss.Attributes{
		attrUsername:           "b",
		attrRecoverToken:       testStdBase64Token,
		attrRecoverTokenExpiry: time.Now().Add(time.Duration(24) * time.Hour),
	}

	if errPage := m.recoverComplete(ctx); errPage != nil {
		t.Error("Expected nil err page")
	}

	password, ok := storer.Users["b"].String(attrPassword)
	if !ok {
		panic("cannot find password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte("a")); err != nil {
		t.Error("Unexpected encrypted password")
	}

	recoverToken, ok := storer.Users["b"].String(attrRecoverToken)
	if !ok {
		panic("cannot find token")
	}
	if recoverToken != "" {
		t.Error("Unexpected recover token:", recoverToken)
	}

	recoverTokenExpiry, ok := storer.Users["b"].DateTime(attrRecoverTokenExpiry)
	if !ok {
		panic("cannot find token")
	}
	var nullTime time.Time
	if recoverTokenExpiry != nullTime {
		t.Error("Unexpected recover token expiry:", recoverTokenExpiry)
	}
}

func Test_recoverCompleteHandlerFunc_OtherMethods(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()

	for i, method := range []string{"HEAD", "PUT", "DELETE", "TRACE", "CONNECT"} {
		w, r, _ := testHttpRequest(method, "/recover/complete", nil)

		m.recoverHandlerFunc(nil, w, r)

		if http.StatusMethodNotAllowed != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, http.StatusMethodNotAllowed, w.Code)
			continue
		}
	}
}
