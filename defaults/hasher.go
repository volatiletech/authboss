package defaults

import "golang.org/x/crypto/bcrypt"

type BCryptHasher struct {
	cost int
}

func NewBCryptHasher(cost int) *BCryptHasher {
	return &BCryptHasher{cost: cost}
}

func (h *BCryptHasher) GenerateHash(raw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), h.cost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}
