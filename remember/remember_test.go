package remember

import (
	"testing"

	"gopkg.in/authboss.v0"
)

func TestMakeToken(t *testing.T) {
	tok, err := R.New(authboss.NewContext(), "storage", "hello", "world", "5")
	if err != nil {
		t.Error("Unexpected error:", err)
	} else if len(tok) == 0 {
		t.Error("It should have made a token.")
	}
}
