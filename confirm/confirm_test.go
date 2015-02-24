package confirm

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"reflect"
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

	if _, err := c.BeforeGet(ctx); err == nil {
		t.Error("Should stop the get due to attribute missing:", err)
	}

	ctx.User = authboss.Attributes{
		StoreConfirmed: false,
	}

	if interrupt, err := c.BeforeGet(ctx); interrupt != authboss.InterruptAccountNotConfirmed {
		t.Error("Should stop the get due to non-confirm:", interrupt)
	} else if err != nil {
		t.Error(err)
	}

	ctx.User = authboss.Attributes{
		StoreConfirmed: true,
	}

	if interrupt, err := c.BeforeGet(ctx); interrupt != authboss.InterruptNone || err != nil {
		t.Error(interrupt, err)
	}
}

func TestConfirm_AfterRegister(t *testing.T) {
	c := setup()
	ctx := authboss.NewContext()
	log := &bytes.Buffer{}
	authboss.Cfg.LogWriter = log
	authboss.Cfg.Mailer = authboss.LogMailer(log)
	authboss.Cfg.PrimaryID = authboss.StoreUsername

	sentEmail := false

	goConfirmEmail = func(c *Confirm, to, token string) {
		c.confirmEmail(to, token)
		sentEmail = true
	}

	if err := c.AfterRegister(ctx); err != errUserMissing {
		t.Error("Expected it to die with user error:", err)
	}

	ctx.User = authboss.Attributes{authboss.Cfg.PrimaryID: "username"}
	if err := c.AfterRegister(ctx); err == nil || err.(authboss.AttributeErr).Name != "email" {
		t.Error("Expected it to die with e-mail address error:", err)
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
		Error     error
	}{
		{"http://localhost", false, authboss.ClientDataErr{FormValueConfirm}},
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
		ctx, _ := authboss.ContextFromRequest(r)

		err := c.confirmHandler(ctx, w, r)
		if err == nil {
			t.Fatal("%d) Expected an error", i)
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
	ctx.CookieStorer = mocks.NewMockClientStorer()
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
