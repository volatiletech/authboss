package recover

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

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
	clientStorer := mocks.NewMockClientStorer()
	ctx.SessionStorer = clientStorer

	m.recoverCompleteHandlerFunc(ctx, w, r)

	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(actualLog, []byte("recover [token expired]:")) {
		t.Error("Expected logs to start with:", "recover [token expired]:")
	}

	if flash := clientStorer.Values[authboss.FlashErrorKey]; flash != m.config.RecoverTokenExpiredFlash {
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
	sessionStorer := mocks.NewMockClientStorer()
	sessionStorer.Values = map[string]string{authboss.FlashErrorKey: "asdf"}
	ctx.SessionStorer = sessionStorer

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

	clientStorer := mocks.NewMockClientStorer()
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
