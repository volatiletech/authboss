// Package expire implements user session timeouts.
// To take advantage of this the expire.Middleware must be installed
// into your http stack.
package expire

import (
	"errors"
	"net/http"
	"time"

	"gopkg.in/authboss.v0"
)

const (
	// UserLastAction is the session key to retrieve the last action of a user.
	UserLastAction = "last_action"
)

var (
	ErrExpired = errors.New("The user session has expired.")
)

// E is the singleton instance of the expire module which will have been
// configured and ready to use after authboss.Init()
var E *Expire

func init() {
	E = &Expire{}
	authboss.RegisterModule("expire", E)
}

type Expire struct{}

func (e *Expire) Initialize() error {
	authboss.Cfg.Callbacks.Before(authboss.EventGet, e.BeforeAuth)

	return nil
}

func (_ *Expire) Routes() authboss.RouteTable      { return nil }
func (_ *Expire) Storage() authboss.StorageOptions { return nil }

// BeforeAuth ensures the account is not locked.
func (e *Expire) BeforeAuth(ctx *authboss.Context) error {
	if _, ok := ctx.SessionStorer.Get(authboss.SessionKey); !ok {
		return nil
	}

	dateStr, ok := ctx.SessionStorer.Get(UserLastAction)
	if ok {
		if date, err := time.Parse(time.RFC3339, dateStr); err != nil {
			Touch(ctx.SessionStorer)
		} else if time.Now().UTC().After(date.Add(authboss.Cfg.ExpireAfter)) {
			ctx.SessionStorer.Del(authboss.SessionKey)
			return ErrExpired
		}
	}

	return nil
}

// Touch updates the last action for the user, so he doesn't become expired.
func Touch(session authboss.ClientStorer) {
	session.Put(UserLastAction, time.Now().UTC().Format(time.RFC3339))
}

type middleware struct {
	sessionMaker authboss.SessionStoreMaker
	next         http.Handler
}

// Middleware ensures that the user's expiry information is kept up-to-date
// on each request.
func Middleware(sessionMaker authboss.SessionStoreMaker, next http.Handler) http.Handler {
	return middleware{sessionMaker, next}
}

func (m middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := m.sessionMaker(w, r)

	if _, ok := session.Get(authboss.SessionKey); ok {
		Touch(session)
	}

	m.next.ServeHTTP(w, r)
}
