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
	"log"

	"gopkg.in/authboss.v0"
)

const (
	// RememberKey is used for cookies and form input names.
	RememberKey = "rm"
	nRandBytes  = 32
)

var (
	errUserMissing = errors.New("remember: User not loaded in callback")
)

// TokenStorer must be implemented in order to satisfy the remember module's
// storage requirements. If the implementer is a typical database then
// the tokens should be stored in a separate table since they require a 1-n
// with the user for each device the user wishes to remain logged in on.
type TokenStorer interface {
	authboss.Storer
	// AddToken saves a new token for the key.
	AddToken(key, token string) error
	// DelTokens removes all tokens for a given key.
	DelTokens(key string) error
	// UseToken finds the key-token pair, removes the entry in the store
	// and returns the key that was found. If the token could not be found
	// return "", ErrTokenNotFound
	UseToken(givenKey, token string) (key string, err error)
}

func init() {
	authboss.RegisterModule("remember", &Remember{})
}

type Remember struct{}

func (r *Remember) Initialize() error {
	if authboss.Cfg.Storer == nil {
		return errors.New("remember: Need a TokenStorer")
	}

	if _, ok := authboss.Cfg.Storer.(TokenStorer); !ok {
		return errors.New("remember: TokenStorer required for remember me functionality")
	}

	authboss.Cfg.Callbacks.Before(authboss.EventGet, r.auth)
	authboss.Cfg.Callbacks.After(authboss.EventAuth, r.afterAuth)

	return nil
}

func (r *Remember) Routes() authboss.RouteTable {
	return nil
}

func (r *Remember) Storage() authboss.StorageOptions {
	return nil
}

// afterAuth is called after authentication is successful.
func (r *Remember) afterAuth(ctx *authboss.Context) error {
	if val, ok := ctx.FirstPostFormValue(RememberKey); !ok || val != "true" {
		return nil
	}

	if ctx.User == nil {
		return errUserMissing
	}

	key, err := ctx.User.StringErr(authboss.Cfg.PrimaryID)
	if err != nil {
		return err
	}

	if _, err := r.new(ctx.CookieStorer, key); err != nil {
		return fmt.Errorf("remember: Failed to create remember token: %v", err)
	}

	return nil
}

// new generates a new remember token and stores it in the configured TokenStorer.
// The return value is a token that should only be given to a user if the delivery
// method is secure which means at least signed if not encrypted.
func (r *Remember) new(cstorer authboss.ClientStorer, storageKey string) (string, error) {
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
	if err := authboss.Cfg.Storer.(TokenStorer).AddToken(storageKey, storageToken); err != nil {
		return "", err
	}

	// Write the finalToken to the cookie
	cstorer.Put(RememberKey, finalToken)

	return finalToken, nil
}

// auth takes a token that was given to a user and checks to see if something
// is matching in the database. If something is found the old token is deleted
// and a new one should be generated. The return value is the key of the
// record who owned this token.
func (r *Remember) auth(ctx *authboss.Context) (authboss.Interrupt, error) {
	if val, ok := ctx.SessionStorer.Get(authboss.SessionKey); ok || len(val) > 0 {
		return authboss.InterruptNone, nil
	}

	finalToken, ok := ctx.CookieStorer.Get(RememberKey)
	if !ok {
		return authboss.InterruptNone, nil
	}

	log.Println("finalToken", finalToken)

	token, err := base64.URLEncoding.DecodeString(finalToken)
	if err != nil {
		return authboss.InterruptNone, err
	}

	log.Println("token", token)

	index := bytes.IndexByte(token, ';')
	if index < 0 {
		return authboss.InterruptNone, errors.New("remember: Invalid remember me token.")
	}

	// Get the key.
	givenKey := token[:index]
	log.Println("key", givenKey)

	// Verify the tokens match.
	sum := md5.Sum(token)

	key, err := authboss.Cfg.Storer.(TokenStorer).UseToken(string(givenKey), base64.StdEncoding.EncodeToString(sum[:]))
	log.Println("lookup", key, err)
	if err == authboss.ErrTokenNotFound {
		return authboss.InterruptNone, nil
	} else if err != nil {
		return authboss.InterruptNone, err
	}

	// Ensure a half-auth.
	ctx.SessionStorer.Put(authboss.SessionHalfAuthKey, "true")
	// Log the user in.
	ctx.SessionStorer.Put(authboss.SessionKey, string(givenKey))

	return authboss.InterruptNone, nil
}
