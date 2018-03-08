package recover

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
)

const (
	testURLBase64Token = "glL8qvO1YKmLxoyEQwVQPpUMM13f6_e4R-2hUQDzP2g="
	testStdBase64Token = "cn0uhfu5Ar2A2JsSs/zdj93zhC1lHJDyIhUYdSgyp71XL/nRb3be/I6AeMz4DACwTRqRAJ6loJedJyOcOtU1Jg=="
)

func TestInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	mailRenderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.ViewRenderer = renderer
	ab.Config.Core.MailRenderer = mailRenderer
	ab.Config.Core.ErrorHandler = errHandler

	r := &Recover{}
	if err := r.Init(ab); err != nil {
		t.Fatal(err)
	}

	if err := renderer.HasLoadedViews(PageRecoverStart, PageRecoverEnd); err != nil {
		t.Error(err)
	}
	if err := mailRenderer.HasLoadedViews(EmailRecoverHTML, EmailRecoverTxt); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/recover", "/recover/end"); err != nil {
		t.Error(err)
	}
	if err := router.HasPosts("/recover", "/recover/end"); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	recover *Recover
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

	harness.ab.Paths.RecoverOK = "/recover/ok"

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Mailer = harness.mailer
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Core.MailRenderer = harness.renderer
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.recover = &Recover{harness.ab}

	return harness
}

func TestStartGet(t *testing.T) {
	t.Parallel()

	h := testSetup()

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.StartGet(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("code was wrong:", w.Code)
	}
	if h.responder.Page != PageRecoverStart {
		t.Error("page was wrong:", h.responder.Page)
	}
	if h.responder.Data != nil {
		t.Error("expected no data:", h.responder.Data)
	}
}

func TestStartPostSuccess(t *testing.T) {
	// no t.Parallel(), global var mangling

	oldRecoverEmail := goRecoverEmail
	goRecoverEmail = func(r *Recover, ctx context.Context, to, token string) {
		r.SendRecoverEmail(ctx, to, token)
	}

	defer func() {
		goRecoverEmail = oldRecoverEmail
	}()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		PID: "test@test.com",
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:    "test@test.com",
		Password: "i can't recall, doesn't seem like something bcrypted though",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.StartPost(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if h.redirector.Options.RedirectPath != h.ab.Config.Paths.RecoverOK {
		t.Error("page was wrong:", h.responder.Page)
	}
	if len(h.redirector.Options.Success) == 0 {
		t.Error("expected a nice success message")
	}

	if h.mailer.Email.To[0] != "test@test.com" {
		t.Error("e-mail to address is wrong:", h.mailer.Email.To)
	}
	if !strings.HasSuffix(h.mailer.Email.Subject, "Password Reset") {
		t.Error("e-mail subject line is wrong:", h.mailer.Email.Subject)
	}
	if len(h.renderer.Data[DataRecoverURL].(string)) == 0 {
		t.Errorf("the renderer's url in data was missing: %#v", h.renderer.Data)
	}
}

func TestStartPostFailure(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		PID: "test@test.com",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.StartPost(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if h.redirector.Options.RedirectPath != h.ab.Config.Paths.RecoverOK {
		t.Error("page was wrong:", h.responder.Page)
	}
	if len(h.redirector.Options.Success) == 0 {
		t.Error("expected a nice success message")
	}

	if len(h.mailer.Email.To) != 0 {
		t.Error("should not have sent an e-mail out!")
	}
}

func TestEndGet(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: "abcd",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndGet(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("code was wrong:", w.Code)
	}
	if h.responder.Page != PageRecoverEnd {
		t.Error("page was wrong:", h.responder.Page)
	}
	if h.responder.Data[DataRecoverToken].(string) != "abcd" {
		t.Errorf("recovery token is wrong: %#v", h.responder.Data)
	}
}

func TestEndPostSuccess(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: testURLBase64Token,
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:              "test@test.com",
		Password:           "to-overwrite",
		RecoverToken:       testStdBase64Token,
		RecoverTokenExpiry: time.Now().UTC().AddDate(0, 0, 1),
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if p := h.redirector.Options.RedirectPath; p != h.ab.Paths.RecoverOK {
		t.Error("path was wrong:", p)
	}
	if len(h.session.ClientValues[authboss.SessionKey]) != 0 {
		t.Error("should not have logged in the user")
	}
	if !strings.Contains(h.redirector.Options.Success, "recovered password") {
		t.Error("should not talk about logging in")
	}
	if strings.Contains(h.redirector.Options.Success, "logged in") {
		t.Error("should not talk about logging in")
	}
}

func TestEndPostSuccessLogin(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.ab.Config.Modules.RecoverLoginAfterRecovery = true
	h.bodyReader.Return = &mocks.Values{
		Token: testURLBase64Token,
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:              "test@test.com",
		Password:           "to-overwrite",
		RecoverToken:       testStdBase64Token,
		RecoverTokenExpiry: time.Now().UTC().AddDate(0, 0, 1),
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(h.ab.NewResponse(w), r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", w.Code)
	}
	if p := h.redirector.Options.RedirectPath; p != h.ab.Paths.RecoverOK {
		t.Error("path was wrong:", p)
	}
	if len(h.session.ClientValues[authboss.SessionKey]) == 0 {
		t.Error("it should have logged in the user")
	}
	if !strings.Contains(h.redirector.Options.Success, "logged in") {
		t.Error("should talk about logging in")
	}
}

func TestEndPostInvalidBase64(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: "a",
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	invalidCheck(t, h, w)
}

func TestEndPostExpiredToken(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: testURLBase64Token,
	}
	h.storer.Users["test@test.com"] = &mocks.User{
		Email:              "test@test.com",
		Password:           "to-overwrite",
		RecoverToken:       testStdBase64Token,
		RecoverTokenExpiry: time.Now().UTC().AddDate(0, 0, -1),
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	invalidCheck(t, h, w)
}

func TestEndPostUserNotExist(t *testing.T) {
	t.Parallel()

	h := testSetup()

	h.bodyReader.Return = &mocks.Values{
		Token: testURLBase64Token,
	}

	r := mocks.Request("GET")
	w := httptest.NewRecorder()

	if err := h.recover.EndPost(w, r); err != nil {
		t.Error(err)
	}

	invalidCheck(t, h, w)
}

func invalidCheck(t *testing.T, h *testHarness, w *httptest.ResponseRecorder) {
	t.Helper()

	if w.Code != http.StatusOK {
		t.Error("code was wrong:", w.Code)
	}
	if h.responder.Page != PageRecoverEnd {
		t.Error("page was wrong:", h.responder.Page)
	}
	if h.responder.Data[authboss.DataValidation].(authboss.ErrorList)[0].Error() != "recovery token is invalid" {
		t.Error("expected a vague error to mislead")
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
