package authboss

import (
	"golang.org/x/crypto/bcrypt"
)

// Hasher is the interface that wraps the hashing and comparison of passwords
type Hasher interface {
	CompareHashAndPassword(hash, password string) error
	GenerateHash(password string) (string, error)
}

// NewBCryptHasher creates a new bcrypt hasher with the given cost
func NewBCryptHasher(cost int) *bcryptHasher {
	return &bcryptHasher{cost: cost}
}

type bcryptHasher struct {
	cost int
}

func (h *bcryptHasher) GenerateHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (h *bcryptHasher) CompareHashAndPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
