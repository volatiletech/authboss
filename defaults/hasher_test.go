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

	if err := hasher.CompareHashAndPassword(hash, "qwerty"); err != nil {
		t.Error("compare-hash-and-password for valid password must be ok", err)
	}

	if err := hasher.CompareHashAndPassword(hash, "qwerty-invalid"); err == nil {
		t.Error("compare-hash-and-password for invalid password must fail")
	}
}
