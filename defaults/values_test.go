package defaults

import (
	"testing"

	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
)

func TestHTTPFormReader(t *testing.T) {
	t.Parallel()

	h := NewHTTPFormReader(false)
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
