package recover

import (
	"bytes"

	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
	"gopkg.in/authboss.v0/internal/views"
)

func Test_Initialize(t *testing.T) {
	t.Parallel()

	config := &authboss.Config{ViewsPath: os.TempDir()}
	m := &RecoverModule{}

	if err := m.Initialize(config); err == nil {
		t.Error("Expected error")
	} else if err.Error() != "recover: Need a RecoverStorer." {
		t.Error("Got error but wrong reason:", err)
	}
	config.Storer = mocks.MockFailStorer{}

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
	sessionStorer := mocks.NewMockClientStorer()
	ctx.SessionStorer = sessionStorer

	return w, r, ctx
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
