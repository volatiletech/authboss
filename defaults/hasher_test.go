package defaults

import (
	"golang.org/x/crypto/bcrypt"
	"strings"
	"testing"
)

func TestHasher(t *testing.T) {
	t.Parallel()

	hasher := NewBCryptHasher(bcrypt.DefaultCost)

	hash, err := hasher.GenerateHash("qwerty")
	if err != nil {
		t.Error(err)
	}

	if hash == "" {
		t.Error("Result Hash must be not empty")

	}
	if len(hash) != 60 {
		t.Error("hash was invalid length", len(hash))
	}
	if !strings.HasPrefix(hash, "$2a$10$") {
		t.Error("hash was wrong", hash)
	}
}
