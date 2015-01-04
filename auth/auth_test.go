package auth

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuth_loginHandler_GET(t *testing.T) {
	tests := []struct {
		InLoginPage io.ReadWriter
		OutBody     string
	}{
		{nil, htmlLoginPage},
		{bytes.NewBufferString("<form></form>"), "<form></form>"},
	}

	for i, test := range tests {
		var c authConfig
		if test.InLoginPage == nil {
			c = NewAuthConfig()
		} else {
			c = authConfig{LoginPage: test.InLoginPage}
		}

		a := NewAuth(c)
		w := httptest.NewRecorder()
		r, err := http.NewRequest("GET", "/login", nil)
		if err != nil {
			t.Errorf("%d> Unexpected error: %s", i, err)
		}

		a.loginHandler(w, r)

		if http.StatusOK != w.Code {
			t.Errorf("%d> Expected response code 200, got %d", i, w.Code)
		}
		if test.OutBody != w.Body.String() {
			t.Errorf("%d> Expected body '%s', got '%s'", i, test.OutBody, w.Body.String())
		}
	}
}
