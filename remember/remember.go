// Package remember implements persistent logins through (typically) cookie session
// storages. The SessionStorer implementation must be fully secure either over https
// or using signed cookies or it is easily exploitable.
package remember

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"gopkg.in/authboss.v0"
)

const nRandBytes = 32

// R is the singleton instance of the remember module which will have been
// configured and ready to use after authboss.Init()
var R *Remember

func init() {
	R = &Remember{}
	authboss.RegisterModule("remember", R)
}

type Remember struct {
	storer authboss.TokenStorer
}

func (r *Remember) Initialize(c *authboss.Config) error {
	if storer, ok := c.Storer.(authboss.TokenStorer); !ok {
		return errors.New("Remember module requires a TokenStorer interface be satisfied.")
	} else {
		r.storer = storer
	}

	return nil
}

func (r *Remember) Routes() authboss.RouteTable {
	return nil
}

func (r *Remember) Storage() authboss.StorageOptions {
	return nil
}

// New generates a new remember token and stores it in the configured TokenStorer.
// The return value is a token that should only be given to a user if the delivery
// method is secure which means at least signed if not encrypted.
func (r *Remember) New(ctx *authboss.Context, storageKey string, keys ...string) (string, error) {
	token := make([]byte, nRandBytes)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}

	for _, k := range keys {
		token = append(token, []byte(k)...)
	}

	sum := md5.Sum(token)
	finalToken := base64.URLEncoding.EncodeToString(token)
	storageToken := base64.StdEncoding.EncodeToString(sum[:])

	if err := r.storer.AddToken(storageKey, storageToken); err != nil {
		return "", err
	}

	return finalToken, nil
}

// Auth takes a token that was given to a user and checks to see if something
// is matching in the database. If something is found the old token is deleted
// and a new one should be generated. The return value is the key of the
// record who owned this token.
func (r *Remember) Auth(ctx *authboss.Context, finalToken string) (string, error) {
	token, err := base64.URLEncoding.DecodeString(finalToken)
	if err != nil {
		return "", err
	}

	sum := md5.Sum(token)
	key, err := r.storer.UseToken(base64.StdEncoding.EncodeToString(sum[:]))
	if err == authboss.TokenNotFound {
		return "", nil
	} else if err != nil {
		return "", err
	}

	return key, nil
}
