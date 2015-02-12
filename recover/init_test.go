package recover

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

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

	successFlash := ctx.SessionStorer.(*mocks.MockClientStorer).Values[authboss.FlashSuccessKey]
	if successFlash != m.config.RecoverInitiateSuccessFlash {
		t.Error("Unexpected success flash message:", successFlash)
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

func Test_sendRecoverEmail_FailToSend(t *testing.T) {
	t.Parallel()
	m, logger := testValidRecoverModule()

	mailer := mocks.NewMockMailer()
	mailer.SendErr = "explode"
	m.config.Mailer = mailer
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
