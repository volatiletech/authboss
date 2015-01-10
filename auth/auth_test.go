package auth

import (
	"net/http"
	"testing"

	"bytes"

	"reflect"

	"net/http/httptest"

	"gopkg.in/authboss.v0"
)

func TestAuth_Initialize_LoadsDefaultLoginPageWhenOverrideNotSpecified(t *testing.T) {
	t.Parallel()

	a := &Auth{}
	if err := a.Initialize(&authboss.Config{}); err != nil {
		t.Errorf("Unexpected config error: %v", err)
	}

	bindata, err := views_login_tpl_bytes()
	if err != nil {
		t.Errorf("Unexpected bindata error: %v", err)
	}

	if !bytes.Equal(a.loginPage.Bytes(), bindata) {
		t.Errorf("Expected '%s', got '%s'", bindata, a.loginPage.Bytes())
	}
}

/*func TestAuth_Initialize_LoadsSpecifiedLoginPageWhenOverrideSpecified(t *testing.T) {
	t.Parallel()

	a := &Auth{}
	if err := a.Initialize(&authboss.Config{
		AuthLoginPageURI: "auth_test.go",
	}); err != nil {
		t.Errorf("Unexpected config error: %v", err)
	}

	file, err := ioutil.ReadFile("auth_test.go")
	if err != nil {
		t.Errorf("Unexpected bindata error: %v", err)
	}

	if !bytes.Equal(a.loginPage.Bytes(), file) {
		t.Errorf("Expected '%s', got '%s'", file, a.loginPage.Bytes())
	}
}*/

func TestAuth_Initialize_RegistersRoutes(t *testing.T) {
	t.Parallel()

	a := &Auth{}
	if err := a.Initialize(&authboss.Config{}); err != nil {
		t.Errorf("Unexpected config error: %v", err)
	}

	if handler, ok := a.routes["login"]; !ok {
		t.Error("Expected route 'login' but was not found'")
	} else if reflect.ValueOf(handler).Pointer() != reflect.ValueOf(a.loginHandler).Pointer() {
		t.Errorf("Expcted func 'loginHandler' but was not found")
	}

	if handler, ok := a.routes["logout"]; !ok {
		t.Error("Expected route 'logout' but was not found'")
	} else if reflect.ValueOf(handler).Pointer() != reflect.ValueOf(a.logoutHandler).Pointer() {
		t.Errorf("Expcted func 'logoutHandler' but was not found")
	}
}

func TestAuth_Routes(t *testing.T) {
	t.Parallel()

	routes := authboss.RouteTable{
		"a": func(_ http.ResponseWriter, _ *http.Request) {},
		"b": func(_ http.ResponseWriter, _ *http.Request) {},
	}
	a := Auth{routes: routes}

	if !reflect.DeepEqual(routes, a.Routes()) {
		t.Errorf("Failed to retrieve routes")
	}
}

func TestAuth_loginHandler_GET(t *testing.T) {
	t.Parallel()

	a := &Auth{}
	if err := a.Initialize(&authboss.Config{}); err != nil {
		t.Errorf("Unexpected config error: %$", err)
	}

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/login", nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	bindata, err := views_login_tpl_bytes()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	a.loginHandler(w, r)

	if http.StatusOK != w.Code {
		t.Errorf("%Expected response code %d, got %d", http.StatusOK, w.Code)
	}
	if !bytes.Equal(bindata, w.Body.Bytes()) {
		t.Errorf("Expected body '%s', got '%s'", string(bindata), w.Body.String())
	}
}

func TestAuth_logoutHandler_GET(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Config       *authboss.Config
		RedirectPath string
	}{
		{&authboss.Config{}, "/"},
		{&authboss.Config{AuthLogoutRoute: "/logout"}, "/logout"},
		{&authboss.Config{MountPath: "/auth", AuthLogoutRoute: "/logout"}, "/auth/logout"},
	}

	for i, test := range tests {
		a := Auth{}
		if err := a.Initialize(test.Config); err != nil {
			t.Errorf("%d> Unexpected config error: %v", i, err)
		}

		w := httptest.NewRecorder()
		r, err := http.NewRequest("GET", "/logout", nil)
		if err != nil {
			t.Errorf("%d> Unexpected error: %v", i, err)
		}

		a.logoutHandler(w, r)

		if http.StatusTemporaryRedirect != w.Code {
			t.Errorf("%d> Expected response code %d, got %d", i, http.StatusTemporaryRedirect, w.Code)
		}
		if test.RedirectPath != w.HeaderMap["Location"][0] {
			t.Errorf("%d> Expected header Location '%s', got '%s'", 1, test.RedirectPath, w.HeaderMap["Location"][0])
		}
	}

}
