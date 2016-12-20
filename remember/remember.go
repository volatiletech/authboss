// Package remember implements persistent logins through the cookie storer.
package remember

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/authboss.v1"
)

const (
	nRandBytes = 32
)

var (
	errUserMissing = errors.New("remember: User not loaded in callback")
)

// RememberStorer must be implemented in order to satisfy the remember module's
// storage requirements. If the implementer is a typical database then
// the tokens should be stored in a separate table since they require a 1-n
// with the user for each device the user wishes to remain logged in on.
//
// Remember storer will look at both authboss's configured Storer and OAuth2Storer
// for compatibility.
type RememberStorer interface {
	// AddToken saves a new token for the key.
	AddToken(key, token string) error
	// DelTokens removes all tokens for a given key.
	DelTokens(key string) error
	// UseToken finds the key-token pair, removes the entry in the store
	// and returns nil. If the token could not be found return ErrTokenNotFound.
	UseToken(givenKey, token string) (err error)
}

func init() {
	authboss.RegisterModule("remember", &Remember{})
}

// Remember module
type Remember struct {
	*authboss.Authboss
}

// Initialize module
func (r *Remember) Initialize(ab *authboss.Authboss) error {
	r.Authboss = ab

	if r.Storer != nil || r.OAuth2Storer != nil {
		if _, ok := r.Storer.(RememberStorer); !ok {
			if _, ok := r.OAuth2Storer.(RememberStorer); !ok {
				return errors.New("remember: RememberStorer required for remember functionality")
			}
		}
	} else if r.StoreMaker == nil && r.OAuth2StoreMaker == nil {
		return errors.New("remember: Need a RememberStorer")
	}

	r.Callbacks.Before(authboss.EventGetUserSession, r.auth)
	r.Callbacks.After(authboss.EventAuth, r.afterAuth)
	r.Callbacks.After(authboss.EventOAuth, r.afterOAuth)
	r.Callbacks.After(authboss.EventPasswordReset, r.afterPassword)

	return nil
}

// Routes for module
func (r *Remember) Routes() authboss.RouteTable {
	return nil
}

// Storage requirements
func (r *Remember) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		r.PrimaryID: authboss.String,
	}
}

// afterAuth is called after authentication is successful.
func (r *Remember) afterAuth(ctx *authboss.Context) error {
	if val := ctx.Values[authboss.CookieRemember]; val != "true" {
		return nil
	}

	if ctx.User == nil {
		return errUserMissing
	}

	key, err := ctx.User.StringErr(r.PrimaryID)
	if err != nil {
		return err
	}

	if _, err := r.new(ctx.CookieStorer, key); err != nil {
		return fmt.Errorf("remember: Failed to create remember token: %v", err)
	}

	return nil
}

// afterOAuth is called after oauth authentication is successful.
// Has to pander to horrible state variable packing to figure out if we want
// to be remembered.
func (r *Remember) afterOAuth(ctx *authboss.Context) error {
	sessValues, ok := ctx.SessionStorer.Get(authboss.SessionOAuth2Params)
	if !ok {
		return nil
	}

	var values map[string]string
	if err := json.Unmarshal([]byte(sessValues), &values); err != nil {
		return err
	}

	val, ok := values[authboss.CookieRemember]
	should := ok && val == "true"

	if !should {
		return nil
	}

	if ctx.User == nil {
		return errUserMissing
	}

	uid, err := ctx.User.StringErr(authboss.StoreOAuth2Provider)
	if err != nil {
		return err
	}
	provider, err := ctx.User.StringErr(authboss.StoreOAuth2Provider)
	if err != nil {
		return err
	}

	if _, err := r.new(ctx.CookieStorer, uid+";"+provider); err != nil {
		return fmt.Errorf("remember: Failed to create remember token: %v", err)
	}

	return nil
}

// afterPassword is called after the password has been reset.
func (r *Remember) afterPassword(ctx *authboss.Context) error {
	if ctx.User == nil {
		return nil
	}

	id, ok := ctx.User.String(r.PrimaryID)
	if !ok {
		return nil
	}

	ctx.CookieStorer.Del(authboss.CookieRemember)

	var storer RememberStorer
	if storer, ok = ctx.Storer.(RememberStorer); !ok {
		if storer, ok = ctx.OAuth2Storer.(RememberStorer); !ok {
			return nil
		}
	}

	return storer.DelTokens(id)
}

// new generates a new remember token and stores it in the configured RememberStorer.
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

	var storer RememberStorer
	var ok bool
	if storer, ok = r.Storer.(RememberStorer); !ok {
		storer, ok = r.OAuth2Storer.(RememberStorer)
	}

	// Save the token in the DB
	if err := storer.AddToken(storageKey, storageToken); err != nil {
		return "", err
	}

	// Write the finalToken to the cookie
	cstorer.Put(authboss.CookieRemember, finalToken)

	return finalToken, nil
}

// auth takes a token that was given to a user and checks to see if something
// is matching in the database. If something is found the old token is deleted
// and a new one should be generated.
func (r *Remember) auth(ctx *authboss.Context) (authboss.Interrupt, error) {
	if val, ok := ctx.SessionStorer.Get(authboss.SessionKey); ok || len(val) > 0 {
		return authboss.InterruptNone, nil
	}

	finalToken, ok := ctx.CookieStorer.Get(authboss.CookieRemember)
	if !ok {
		return authboss.InterruptNone, nil
	}

	token, err := base64.URLEncoding.DecodeString(finalToken)
	if err != nil {
		return authboss.InterruptNone, err
	}

	index := bytes.IndexByte(token, ';')
	if index < 0 {
		return authboss.InterruptNone, errors.New("remember: Invalid remember token")
	}

	// Get the key.
	givenKey := string(token[:index])

	// Verify the tokens match.
	sum := md5.Sum(token)

	var storer RememberStorer
	if storer, ok = ctx.Storer.(RememberStorer); !ok {
		storer, ok = ctx.OAuth2Storer.(RememberStorer)
	}

	err = storer.UseToken(givenKey, base64.StdEncoding.EncodeToString(sum[:]))
	if err == authboss.ErrTokenNotFound {
		return authboss.InterruptNone, nil
	} else if err != nil {
		return authboss.InterruptNone, err
	}

	_, err = r.new(ctx.CookieStorer, givenKey)
	if err != nil {
		return authboss.InterruptNone, err
	}

	// Ensure a half-auth.
	ctx.SessionStorer.Put(authboss.SessionHalfAuthKey, "true")
	// Log the user in.
	ctx.SessionStorer.Put(authboss.SessionKey, givenKey)

	return authboss.InterruptNone, nil
}
