package auth

import (
	"testing"

	"bytes"

	"io/ioutil"

	"net/http"

	"html/template"

	"net/http/httptest"

	"net/url"
	"strings"

	"gopkg.in/authboss.v0"
)

func getCompiledTemplate(path string, data interface{}) (b *bytes.Buffer, err error) {
	var file []byte
	if file, err = ioutil.ReadFile(path); err != nil {
		return nil, err
	}

	var tpl *template.Template
	if tpl, err = template.New("tpl").Parse(string(file)); err != nil {
		return nil, err
	}

	b = &bytes.Buffer{}
	if err = tpl.Execute(b, data); err != nil {
		return nil, err
	}

	return b, nil
}

func TestAuth_Storage(t *testing.T) {
	t.Parallel()

	a := &Auth{}
	if err := a.Initialize(authboss.NewConfig()); err != nil {
		t.Errorf("Unexpected config error: %v", err)
	}
	options := a.Storage()

	tests := []struct {
		Name string
		Type authboss.DataType
	}{
		{"username", authboss.String},
		{"password", authboss.String},
	}

	for i, test := range tests {
		if value, ok := options[test.Name]; !ok {
			t.Errorf("%d> Expected key %s", i, test.Name)
			continue
		} else if value != test.Type {
			t.Errorf("$d> Expected key %s to have value %v, got %v", i, test.Name, test.Type, value)
			continue
		}
	}
}

func TestAuth_Routes(t *testing.T) {
	t.Parallel()

	a := &Auth{}
	if err := a.Initialize(authboss.NewConfig()); err != nil {
		t.Errorf("Unexpected config error: %v", err)
	}
	routes := a.Routes()

	tests := []struct {
		Route string
	}{
		{"login"},
		{"logout"},
	}

	for i, test := range tests {
		if value, ok := routes[test.Route]; !ok {
			t.Errorf("%d> Expected key %s", i, test.Route)
		} else if value == nil {
			t.Errorf("%d> Expected key %s to have func", i, test.Route)
		}
	}
}

func TestAuth_loginHandlerFunc_GET(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Config *authboss.Config
	}{
		{authboss.NewConfig()},
		{&authboss.Config{}},
		{&authboss.Config{ViewsPath: "views"}},
	}

	for i, test := range tests {
		a := &Auth{}
		if err := a.Initialize(test.Config); err != nil {
			t.Errorf("%d> Unexpected config error: %v", i, err)
			continue
		}

		r, err := http.NewRequest("GET", "/login", nil)
		if err != nil {
			t.Errorf("Unexpected error '%s'", err)
		}
		w := httptest.NewRecorder()

		a.loginHandlerFunc(nil, w, r)

		if tpl, err := getCompiledTemplate("views/login.tpl", nil); err != nil {
			t.Errorf("%d> Unexpected error '%s'", i, err)
			continue
		} else {
			if !bytes.Equal(tpl.Bytes(), w.Body.Bytes()) {
				t.Errorf("%d> Expected '%s', got '%s'", i, tpl.Bytes(), w.Body.Bytes())
				continue
			}
		}
	}
}

func TestAuth_loginHandlerFunc_POST(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Username, Password string
		StatusCode         int
		Location           string
		BodyData           *AuthPage
	}{
		{"john", "1234", http.StatusFound, "/dashboard", nil},
		{"jane", "1234", http.StatusForbidden, "", &AuthPage{"invalid username and/or password", "jane"}},
		{"mike", "", http.StatusForbidden, "", &AuthPage{"invalid username and/or password", "jane"}},
	}

	c := authboss.NewConfig()
	c.Storer = NewMockUserStorer()
	c.AuthLoginSuccessRoute = "/dashboard"

	for i, test := range tests {
		a := &Auth{}
		if err := a.Initialize(c); err != nil {
			t.Errorf("%d> Unexpected config error: %v", i, err)
			continue
		}

		postData := url.Values{}
		postData.Set("username", test.Username)
		postData.Set("password", test.Password)

		r, err := http.NewRequest("POST", "/login", strings.NewReader(postData.Encode()))
		if err != nil {
			t.Errorf("%d> Unexpected error '%s'", i, err)
			continue
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		ctx, err := authboss.ContextFromRequest(r)
		if err != nil {
			t.Errorf("%d> Unexpected error '%s'", i, err)
			continue
		}

		a.loginHandlerFunc(ctx, w, r)

		if test.StatusCode != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, test.StatusCode, w.Code)
			continue
		}

		location := w.Header().Get("Location")
		if test.Location != location {
			t.Errorf("%d> Expected lcoation %s, got %s", i, test.Location, location)
			continue
		}

		if test.BodyData != nil {
			if tpl, err := getCompiledTemplate("views/login.tpl", test.BodyData); err != nil {
				t.Errorf("%d> Unexpected error '%s'", i, err)
				continue
			} else {
				if !bytes.Equal(tpl.Bytes(), w.Body.Bytes()) {
					t.Errorf("%d> Expected '%s', got '%s'", i, tpl.Bytes(), w.Body.Bytes())
					continue
				}
			}
		}
	}
}

func TestAuth_loginHandlerFunc_OtherMethods(t *testing.T) {
	t.Parallel()

	a := Auth{}
	methods := []string{"HEAD", "PUT", "DELETE", "TRACE", "CONNECT"}

	for i, method := range methods {
		r, err := http.NewRequest(method, "/login", nil)
		if err != nil {
			t.Errorf("%d> Unexpected error '%s'", i, err)
		}
		w := httptest.NewRecorder()

		a.loginHandlerFunc(nil, w, r)

		if http.StatusMethodNotAllowed != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, http.StatusMethodNotAllowed, w.Code)
			continue
		}
	}
}

func TestAuth_logoutHandlerFunc_GET(t *testing.T) {
	t.Parallel()

	a := Auth{}
	if err := a.Initialize(&authboss.Config{AuthLogoutRoute: "/dashboard"}); err != nil {
		t.Errorf("Unexpeced config error '%s'", err)
	}
	r, err := http.NewRequest("GET", "/logout", nil)
	if err != nil {
		t.Errorf("Unexpected error '%s'", err)
	}
	w := httptest.NewRecorder()

	a.logoutHandlerFunc(nil, w, r)

	if http.StatusFound != w.Code {
		t.Errorf("Expected status code %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Expected lcoation %s, got %s", "/dashboard", location)
	}
}

func TestAuth_logoutHandlerFunc_OtherMethods(t *testing.T) {
	t.Parallel()

	a := Auth{}
	methods := []string{"HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"}

	for i, method := range methods {
		r, err := http.NewRequest(method, "/logout", nil)
		if err != nil {
			t.Errorf("%d> Unexpected error '%s'", i, err)
		}
		w := httptest.NewRecorder()

		a.logoutHandlerFunc(nil, w, r)

		if http.StatusMethodNotAllowed != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, http.StatusMethodNotAllowed, w.Code)
			continue
		}
	}
}
