package authboss

import (
	"testing"

	"github.com/pkg/errors"
)

func TestClientDataErr(t *testing.T) {
	t.Parallel()

	estr := "Failed to retrieve client attribute: lol"
	err := ClientDataErr{"lol"}
	if str := err.Error(); str != estr {
		t.Error("Error was wrong:", str)
	}
}

func TestRenderErr(t *testing.T) {
	t.Parallel()

	estr := `error rendering response "lol": cause, data: authboss.HTMLData{"a":5}`
	err := RenderErr{"lol", NewHTMLData("a", 5), errors.New("cause")}
	if str := err.Error(); str != estr {
		t.Error("Error was wrong:", str)
	}
}
