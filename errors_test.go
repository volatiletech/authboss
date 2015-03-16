package authboss

import (
	"errors"
	"testing"
)

func TestAttributeErr(t *testing.T) {
	estr := "Failed to retrieve database attribute, type was wrong: lol (want: String, got: int)"
	if str := NewAttributeErr("lol", String, 5).Error(); str != estr {
		t.Error("Error was wrong:", str)
	}

	estr = "Failed to retrieve database attribute: lol"
	err := AttributeErr{Name: "lol"}
	if str := err.Error(); str != estr {
		t.Error("Error was wrong:", str)
	}
}

func TestClientDataErr(t *testing.T) {
	estr := "Failed to retrieve client attribute: lol"
	err := ClientDataErr{"lol"}
	if str := err.Error(); str != estr {
		t.Error("Error was wrong:", str)
	}
}

func TestErrAndRedirect(t *testing.T) {
	estr := "Error: cause, Redirecting to: /"
	err := ErrAndRedirect{errors.New("cause"), "/", "success", "failure"}
	if str := err.Error(); str != estr {
		t.Error("Error was wrong:", str)
	}
}

func TestRenderErr(t *testing.T) {
	estr := `Error rendering template "lol": cause, data: authboss.HTMLData{"a":5}`
	err := RenderErr{"lol", NewHTMLData("a", 5), errors.New("cause")}
	if str := err.Error(); str != estr {
		t.Error("Error was wrong:", str)
	}
}
