package authboss

import (
	"golang.org/x/crypto/bcrypt"
)

type Hasher interface {
	CompareHashAndPassword(hash, password string) error
	GenerateHash(password string) (string, error)
}

func NewBCryptHasher(cost int) Hasher {
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
