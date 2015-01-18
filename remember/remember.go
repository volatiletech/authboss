// Package remember implements persistent logins through (typically) cookie session
// storages. The SessionStorer implementation must be fully secure either over https
// or using signed cookies or it is easily exploitable.
package remember

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"gopkg.in/authboss.v0"
)

const (
	// ValueKey is used for cookies and form input names.
	ValueKey = "rm"
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
	storer        authboss.TokenStorer
	cookieStorer  authboss.ClientStorer
	sessionStorer authboss.ClientStorer
	logger        io.Writer
}

func (r *Remember) Initialize(config *authboss.Config) error {
	if config.Storer == nil {
		return errors.New("remember: Need a TokenStorer.")
	}

	if storer, ok := config.Storer.(authboss.TokenStorer); !ok {
		return errors.New("remember: TokenStorer required for remember me functionality.")
	} else {
		r.storer = storer
	}

	r.logger = c.LogWriter
	config.Callbacks.After(authboss.EventAuth, r.AfterAuth)

	return nil
}

func (r *Remember) Routes() authboss.RouteTable {
	return nil
}

func (r *Remember) Storage() authboss.StorageOptions {
	return nil
}

// AfterAuth is called after authentication is successful.
func (r *Remember) AfterAuth(ctx *authboss.Context) {
	if val, ok := ctx.FirstPostFormValue(ValueKey); !ok || val != "true" {
		return
	}

	if ctx.User == nil {
		fmt.Fprintf(r.logger, "remember: AfterAuth no user loaded")
		return
	}

	keyIntf, ok := ctx.User["username"]
	if !ok {
		fmt.Fprintf(r.logger, "remember: username not present")
		return
	}

	key, ok := keyIntf.(string)
	if !ok {
		fmt.Fprintf(r.logger, "remember: username not a string")
		return
	}

	if _, err := r.New(ctx.CookieStorer, key); err != nil {
		fmt.Fprintf(r.logger, "remember: Failed to create remember token: %v", err)
	}
}

// New generates a new remember token and stores it in the configured TokenStorer.
// The return value is a token that should only be given to a user if the delivery
// method is secure which means at least signed if not encrypted.
func (r *Remember) New(cstorer authboss.ClientStorer, storageKey string) (string, error) {
	token := make([]byte, nRandBytes+len(storageKey)+1)
	copy(token, []byte(storageKey))
	token[len(storageKey)] = ';'

	if _, err := rand.Read(token[len(storageKey)+1:]); err != nil {
		return "", err
	}

	sum := md5.Sum(token)
	finalToken := base64.URLEncoding.EncodeToString(token)
	storageToken := base64.StdEncoding.EncodeToString(sum[:])

	// Save the token in the DB
	if err := r.storer.AddToken(storageKey, storageToken); err != nil {
		return "", err
	}

	// Write the finalToken to the cookie
	cstorer.Put(ValueKey, finalToken)

	return finalToken, nil
}

// Auth takes a token that was given to a user and checks to see if something
// is matching in the database. If something is found the old token is deleted
// and a new one should be generated. The return value is the key of the
// record who owned this token.
func (r *Remember) Auth(
	cstorer authboss.ClientStorer,
	sstorer authboss.ClientStorer,
	finalToken string) (string, error) {

	token, err := base64.URLEncoding.DecodeString(finalToken)
	if err != nil {
		return "", err
	}

	index := bytes.IndexByte(token, ';')
	if index < 0 {
		return "", errors.New("remember: Invalid remember me token.")
	}

	// Get the key.
	givenKey := token[:index]

	// Verify the tokens match.
	sum := md5.Sum(token)

	key, err := r.storer.UseToken(string(givenKey), base64.StdEncoding.EncodeToString(sum[:]))
	if err == authboss.TokenNotFound {
		return "", nil
	} else if err != nil {
		return "", err
	}

	// Ensure a half-auth.
	sstorer.Put(authboss.HalfAuthKey, "true")
	// Log the user in.
	sstorer.Put(authboss.SessionKey, key)

	return key, nil
}
