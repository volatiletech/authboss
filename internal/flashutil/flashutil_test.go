package flashutil

import (
	"testing"

	"gopkg.in/authboss.v0/internal/mocks"
)

func TestPull(t *testing.T) {
	t.Parallel()

	storer := mocks.NewMockClientStorer()
	storer.Values = map[string]string{
		"a": "1",
	}

	v := Pull(storer, "a")

	if v != "1" {
		t.Error(`Expected value "1", got:`, v)
	}

	if len(storer.Values) != 0 {
		t.Error("Expected length of zero")
	}
}
