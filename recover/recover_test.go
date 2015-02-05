package recover

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"os"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

var filenames = []string{
	tplLogin,
	tplRecover,
	tplRecoverComplete,
	tplInitHTMLEmail,
	tplInitTextEmail,
}

func TestMain(main *testing.M) {
	for _, filename := range filenames {
		file, err := os.Create(fmt.Sprintf("%s/%s", os.TempDir(), filename))
		if err != nil {
			panic(err)
		}

		if _, err := file.WriteString(filename); err != nil {

		}
	}

	code := main.Run()

	for _, filename := range filenames {
		os.Remove(filename)
	}

	os.Exit(code)
}

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
	config.ViewsPath = os.TempDir()

	var err error
	if config.Layout, err = template.New("").Parse(`<i>{{template "authboss" .}}</i>`); err != nil {
		panic(err)
	}
	if config.LayoutEmail, _ = template.New("").Parse(`<b>{{template "authboss" .}}</b>`); err != nil {
		panic(err)
	}

	config.Policies = []authboss.Validator{
		authboss.Rules{
			FieldName: "username",
			Required:  true,
		},
	}
	config.ConfirmFields = []string{"username", "confirmUsername"}

	return config
}

func testValidRecoverModule() (*RecoverModule, *bytes.Buffer) {
	c := testValidTestConfig()
	logger := &bytes.Buffer{}
	c.LogWriter = logger

	m := &RecoverModule{}
	if err := m.Initialize(c); err != nil {
		panic(err)
	}

	return m, logger
}

func Test_Routes(t *testing.T) {
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

func Test_Storage(t *testing.T) {
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
	w, r, ctx := testHttpRequest("GET", "/login", nil)

	m.recoverHandlerFunc(ctx, w, r)

	if w.Code != http.StatusOK {
		t.Error("Unexpected code:", w.Code)
	}
	if w.Body.String() != "<i>recover.tpl</i>" {
		t.Error("Unexpected body:", w.Body.String())
	}
}

/*func TestRecoverModule_recoverHandlerFunc_POST(t *testing.T) {
	t.Parallel()
}*/

func Test_recover(t *testing.T) {
	t.Parallel()
	m, logger := testValidRecoverModule()

	page := m.recover(mocks.MockRequestContext())
	if len(page.ErrMap["username"]) != 1 {
		t.Error("Exepted single validation error for username")
	}
	if page.ErrMap["username"][0] != "Cannot be blank" {
		t.Error("Unexpected validation error for username:", page.ErrMap["username"][0])
	}
	expectedLog := []byte("recover [validation failed]: map[username:[Cannot be blank]]\n")
	actualLog, err := ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(expectedLog, actualLog) {
		t.Error("Unexpected logs:", string(expectedLog))
	}

	page = m.recover(mocks.MockRequestContext("username", "a", "confirmUsername", "b"))
	if len(page.ErrMap["username"]) != 0 {
		t.Error("Exepted no validation errors for username")
	}
	if len(page.ErrMap["confirmUsername"]) != 1 {
		t.Error("Exepted single validation error for confirmUsername")
	}
	if page.ErrMap["confirmUsername"][0] != "Does not match username" {
		t.Error("Unexpected validation error for confirmUsername:", page.ErrMap["confirmUsername"][0])
	}
	expectedLog = []byte("recover [validation failed]: map[confirmUsername:[Does not match username]]\n")
	actualLog, err = ioutil.ReadAll(logger)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(expectedLog, actualLog) {
		t.Error("Unexpected logs:", string(expectedLog))
	}

	storer, ok := m.config.Storer.(*mocks.MockStorer)
	if !ok {
		panic("Failed to get storer")
	}
	storer.Users["a"] = authboss.Attributes{"username": "", "password": "", "email", "a@b.c"}

	page = m.recover(mocks.MockRequestContext("username", "a", "confirmUsername", "a"))

	_, ok = storer.Users["a"][attrRecoverToken]
	if !ok {
		t.Error("Expected recover token")
	}

	_, ok = storer.Users["a"][attrRecoverTokenExpiry]
	if !ok {
		t.Error("Expected recover token expiry")
	}

}

func Test_recoverHandlerFunc_OtherMethods(t *testing.T) {
	t.Parallel()

	m, _ := testValidRecoverModule()

	for i, method := range []string{"HEAD", "PUT", "DELETE", "TRACE", "CONNECT"} {
		w, r, _ := testHttpRequest(method, "/login", nil)

		m.recoverHandlerFunc(nil, w, r)

		if http.StatusMethodNotAllowed != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, http.StatusMethodNotAllowed, w.Code)
			continue
		}
	}
}
