package defaults

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
)

func TestHTTPBodyReader(t *testing.T) {
	t.Parallel()

	h := NewHTTPBodyReader(false, false)
	r := mocks.Request("POST", "email", "john@john.john", "password", "flowers")

	validator, err := h.Read("login", r)
	if err != nil {
		t.Error(err)
	}

	uv := validator.(authboss.UserValuer)
	if "john@john.john" != uv.GetPID() {
		t.Error("wrong e-mail:", uv.GetPID())
	}
	if "flowers" != uv.GetPassword() {
		t.Error("wrong password:", uv.GetPassword())
	}
}

func TestHTTPBodyReaderJSON(t *testing.T) {
	t.Parallel()

	h := NewHTTPBodyReader(true, false)
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"john@john.john","password":"flowers"}`))

	validator, err := h.Read("login", r)
	if err != nil {
		t.Error(err)
	}

	uv := validator.(authboss.UserValuer)
	if "john@john.john" != uv.GetPID() {
		t.Error("wrong e-mail:", uv.GetPID())
	}
	if "flowers" != uv.GetPassword() {
		t.Error("wrong password:", uv.GetPassword())
	}
}
