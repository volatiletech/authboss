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

	"gopkg.in/authboss.v1"
	"gopkg.in/authboss.v1/internal/mocks"
)

func setup() *Confirm {
	ab := authboss.New()
	ab.Storer = mocks.NewMockStorer()
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
	ctx.AllowInsecureLoginAfterConfirm = false

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

	if _, ok := ctx.SessionStorer.Get(authboss.SessionKey); ok {
		t.Error("Should not have logged the user in since AllowInsecureLoginAfterConfirm is false.")
	}

	if success, ok := ctx.SessionStorer.Get(authboss.FlashSuccessKey); !ok || len(success) == 0 {
		t.Error("Should have left a nice message.")
	}
}
