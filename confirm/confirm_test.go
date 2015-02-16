package confirm

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

func setup() *Confirm {
	authboss.NewConfig()
	authboss.Cfg.Storer = mocks.NewMockStorer()
	authboss.Cfg.LayoutEmail = template.Must(template.New("").Parse(`email ^_^`))

	c := &Confirm{}
	if err := c.Initialize(); err != nil {
		panic(err)
	}
	return c
}

func TestConfirm_Initialize(t *testing.T) {
	authboss.NewConfig()
	c := &Confirm{}
	if err := c.Initialize(); err == nil {
		t.Error("Should cry about not having a storer.")
	}

	c = setup()

	if c.emailTemplates == nil {
		t.Error("Missing email templates")
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

	c := &Confirm{}
	storage := c.Storage()

	if authboss.String != storage[StoreConfirmToken] {
		t.Error("Expect StoreConfirmToken to be a string.")
	}
	if authboss.Bool != storage[StoreConfirmed] {
		t.Error("Expect StoreConfirmed to be a bool.")
	}
}

func TestConfirm_BeforeGet(t *testing.T) {
	c := setup()
	ctx := authboss.NewContext()

	if err := c.BeforeGet(ctx); err == nil {
		t.Error("Should stop the get due to non-confirm.")
	}

	ctx.User = authboss.Attributes{
		StoreConfirmed: false,
	}

	if err := c.BeforeGet(ctx); err == nil {
		t.Error("Should stop the get due to non-confirm.")
	}

	ctx.User = authboss.Attributes{
		StoreConfirmed: true,
	}

	if err := c.BeforeGet(ctx); err != nil {
		t.Error(err)
	}
}

func TestConfirm_AfterRegister(t *testing.T) {
	c := setup()
	ctx := authboss.NewContext()
	log := &bytes.Buffer{}
	authboss.Cfg.LogWriter = log
	authboss.Cfg.Mailer = authboss.LogMailer(log)

	sentEmail := false

	goConfirmEmail = func(c *Confirm, to, token string) {
		c.confirmEmail(to, token)
		sentEmail = true
	}

	c.AfterRegister(ctx)
	if str := log.String(); !strings.Contains(str, "user not loaded") {
		t.Error("Expected it to die with loading error:", str)
	}

	ctx.User = authboss.Attributes{}
	log.Reset()
	c.AfterRegister(ctx)
	if str := log.String(); !strings.Contains(str, "username doesn't exist") {
		t.Error("Expected it to die with username error:", str)
	}

	ctx.User[authboss.StoreUsername] = "uname"
	log.Reset()
	c.AfterRegister(ctx)
	if str := log.String(); !strings.Contains(str, "no e-mail address to send to") {
		t.Error("Expected it to die with e-mail address error:", str)
	}

	ctx.User[authboss.StoreEmail] = "a@a.com"
	log.Reset()
	c.AfterRegister(ctx)
	if str := log.String(); !strings.Contains(str, "Subject: Confirm New Account") {
		t.Error("Expected it to send an e-mail:", str)
	}

	if !sentEmail {
		t.Error("Expected it to send an e-mail.")
	}
}

func TestConfirm_ConfirmHandlerErrors(t *testing.T) {
	c := setup()
	log := &bytes.Buffer{}
	authboss.Cfg.LogWriter = log
	authboss.Cfg.Mailer = authboss.LogMailer(log)

	tests := []struct {
		URL       string
		Confirmed bool
		Redirect  bool
		Error     string
	}{
		{"http://localhost", false, true, "no confirm token found in request"},
		{"http://localhost?cnf=c$ats", false, true, "confirm token failed to decode"},
		{"http://localhost?cnf=SGVsbG8sIHBsYXlncm91bmQ=", false, true, "token not found"},
	}

	for i, test := range tests {
		r, _ := http.NewRequest("GET", test.URL, nil)
		w := httptest.NewRecorder()
		ctx, _ := authboss.ContextFromRequest(r)

		log.Reset()
		c.confirmHandler(ctx, w, r)

		if len(test.Error) != 0 {
			if str := log.String(); !strings.Contains(str, test.Error) {
				t.Errorf("%d) Expected: %q, got: %q", i, test.Error, str)
			}
		}

		is, ok := ctx.User.Bool(StoreConfirmed)
		if ok && is {
			t.Error("The user should not be confirmed.")
		}

		if test.Redirect && w.Code != http.StatusTemporaryRedirect {
			t.Error("Expected a redirect, got:", w.Header)
		}
	}
}

func TestConfirm_Confirm(t *testing.T) {
	c := setup()
	ctx := authboss.NewContext()
	log := &bytes.Buffer{}
	authboss.Cfg.LogWriter = log
	authboss.Cfg.Mailer = authboss.LogMailer(log)

	// Create a token
	token := []byte("hi")
	sum := md5.Sum(token)

	// Create the "database"
	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer
	user := authboss.Attributes{
		authboss.StoreUsername: "usern",
		StoreConfirmToken:      base64.StdEncoding.EncodeToString(sum[:]),
	}
	storer.Users["usern"] = user

	// Make a request with session and context support.
	r, _ := http.NewRequest("GET", "http://localhost?cnf="+base64.URLEncoding.EncodeToString(token), nil)
	w := httptest.NewRecorder()
	ctx, _ = authboss.ContextFromRequest(r)
	session := mocks.NewMockClientStorer()
	ctx.User = user
	ctx.SessionStorer = session

	c.confirmHandler(ctx, w, r)
	if w.Code != http.StatusTemporaryRedirect {
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
