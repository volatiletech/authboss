package authboss

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"io"
)

type CredsGenerator interface {
	// Generate generates a one-time use 2-part token for authenticating a request.
	// selector: to be stored in the database and ALWAYS used in select query
	// verifier: to be stored in database but NEVER used in select query
	// token: the user-facing base64 encoded selector+verifier
	GenerateCreds() (selector, verifier, token string, err error)

	ParseToken(token string) (selectorBytes, verifierBytes []byte)

	TokenSize() int
}


const (
	tokenSize  = 64
	tokenSplit = tokenSize / 2
)

type Sha512CredsGenerator struct{}

func NewSha512CredsGenerator() *Sha512CredsGenerator {
	return &Sha512CredsGenerator{}
}

// GenerateCreds generates pieces needed as credentials
// selector: hash of the first half of an N byte value
// (to be stored in the database and used in SELECT query)
// verifier: hash of the second half of an N byte value
// (to be stored in database but never used in SELECT query)
// token: the user-facing base64 encoded selector+verifier
func (cg *Sha512CredsGenerator) GenerateCreds() (selector, verifier, token string, err error) {
	rawToken := make([]byte, tokenSize)
	if _, err = io.ReadFull(rand.Reader, rawToken); err != nil {
		return "", "", "", err
	}

	selectorBytes := sha512.Sum512(rawToken[:tokenSplit])
	verifierBytes := sha512.Sum512(rawToken[tokenSplit:])

	return base64.StdEncoding.EncodeToString(selectorBytes[:]),
		base64.StdEncoding.EncodeToString(verifierBytes[:]),
		base64.URLEncoding.EncodeToString(rawToken),
		nil
}

func (cg *Sha512CredsGenerator) ParseToken(rawToken string) (selectorBytes, verifierBytes []byte) {
	selectorBytes64 := sha512.Sum512([]byte(rawToken)[:tokenSplit])
	selectorBytes = selectorBytes64[:]

	verifierBytes64 := sha512.Sum512([]byte(rawToken)[tokenSplit:])
	verifierBytes = verifierBytes64[:]

	return
}

func (cg *Sha512CredsGenerator) TokenSize() int { return tokenSize }
