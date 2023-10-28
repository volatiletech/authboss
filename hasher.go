package authboss

import (
	"errors"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
)

var ErrArgonMismatchedHashAndPassword = errors.New("hashedPassword is not the hash of the given password")

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

func NewArgon2Hasher(params *argon2id.Params) Hasher {
	if params == nil {
		params = argon2id.DefaultParams
	}
	return &argon2Hasher{params: *params}
}

type argon2Hasher struct {
	params argon2id.Params
}

func (h argon2Hasher) GenerateHash(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func (h *argon2Hasher) CompareHashAndPassword(hashedPassword, password string) error {
	matched, err := argon2id.ComparePasswordAndHash(password, hashedPassword)
	if err != nil {
		return err
	}
	if !matched {
		return ErrArgonMismatchedHashAndPassword
	}

	return nil
}
