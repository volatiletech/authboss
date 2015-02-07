// Package lock implements user locking after N bad sign-in attempts.
package lock

import (
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/authboss.v0"
)

const (
	UserAttemptNumber = "attempt_number"
	UserAttemptTime   = "attempt_time"
	UserLocked        = "locked"
)

var (
	ErrLocked = errors.New("Account is locked.")
)

// L is the singleton instance of the lock module which will have been
// configured and ready to use after authboss.Init()
var L *Lock

func init() {
	L = &Lock{}
	authboss.RegisterModule("lock", L)
}

type Lock struct {
	storer authboss.Storer
	logger io.Writer

	attempts int
	window   time.Duration
	duration time.Duration
}

func (l *Lock) Initialize(config *authboss.Config) error {
	if config.Storer == nil {
		return errors.New("lock: Need a Storer.")
	}

	l.logger = config.LogWriter

	l.attempts = config.LockAfter
	l.window = config.LockWindow
	l.duration = config.LockDuration

	// Events
	config.Callbacks.Before(authboss.EventGet, l.BeforeAuth)
	config.Callbacks.Before(authboss.EventAuth, l.BeforeAuth)
	config.Callbacks.After(authboss.EventAuth, l.AfterAuth)
	config.Callbacks.After(authboss.EventAuthFail, l.AfterAuthFail)

	return nil
}

func (l *Lock) Routes() authboss.RouteTable {
	return nil
}

func (l *Lock) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		UserAttemptNumber: authboss.Integer,
		UserAttemptTime:   authboss.DateTime,
		UserLocked:        authboss.Bool,
	}
}

// BeforeAuth ensures the account is not locked.
func (l *Lock) BeforeAuth(ctx *authboss.Context) error {
	if ctx.User == nil {
		return errors.New("lock: user not loaded in before auth callback")
	}

	if intf, ok := ctx.User[UserLocked]; ok {
		if locked, ok := intf.(bool); ok && locked {
			return ErrLocked
		}
	}

	return nil
}

// AfterAuth resets the attempt number field.
func (l *Lock) AfterAuth(ctx *authboss.Context) {
	if ctx.User == nil {
		fmt.Fprintln(l.logger, "lock: user not loaded in after auth callback")
	}

	var username string
	if intf, ok := ctx.User["username"]; !ok {
		fmt.Fprintf(l.logger, "lock: username not present")
		return
	} else if username, ok = intf.(string); !ok {
		fmt.Fprintf(l.logger, "lock: username wrong type")
		return
	}

	ctx.User[UserAttemptNumber] = 0
	ctx.User[UserAttemptTime] = time.Now().UTC()

	if err := ctx.SaveUser(username, l.storer); err != nil {
		fmt.Fprintf(l.logger, "lock: saving user failed %v", err)
	}
}

// AfterAuthFail adjusts the attempt number and time.
func (l *Lock) AfterAuthFail(ctx *authboss.Context) {
	if ctx.User == nil {
		return
	}

	var username string
	if intf, ok := ctx.User["username"]; !ok {
		fmt.Fprintf(l.logger, "lock: username not present")
		return
	} else if username, ok = intf.(string); !ok {
		fmt.Fprintf(l.logger, "lock: username wrong type")
		return
	}

	lastAttempt := time.Now().UTC()
	if attemptTimeIntf, ok := ctx.User[UserAttemptTime]; ok {
		if attemptTime, ok := attemptTimeIntf.(time.Time); ok {
			lastAttempt = attemptTime
		}
	}

	nAttempts := 0
	if attemptsIntf, ok := ctx.User[UserAttemptNumber]; ok {
		if attempts, ok := attemptsIntf.(int); ok {
			nAttempts = attempts
		}
	}

	nAttempts++

	if time.Now().UTC().Sub(lastAttempt) <= l.window {
		if nAttempts >= l.attempts {
			ctx.User[UserLocked] = true
		}

		ctx.User[UserAttemptNumber] = nAttempts
	} else {
		ctx.User[UserAttemptNumber] = 0
	}
	ctx.User[UserAttemptTime] = time.Now().UTC()

	if err := ctx.SaveUser(username, l.storer); err != nil {
		fmt.Fprintf(l.logger, "lock: saving user failed %v", err)
	}
}

// Lock a user manually.
func (l *Lock) Lock(key string, storer authboss.Storer) error {
	user, err := storer.Get(key, authboss.ModuleAttrMeta)
	if err != nil {
		return err
	}

	attr := authboss.Unbind(user)
	if err != nil {
		return err
	}

	attr[UserLocked] = true

	return storer.Put(key, attr)
}

// Unlock a user that was locked by this module.
func (l *Lock) Unlock(key string, storer authboss.Storer) error {
	user, err := storer.Get(key, authboss.ModuleAttrMeta)
	if err != nil {
		return err
	}

	attr := authboss.Unbind(user)
	if err != nil {
		return err
	}

	// Set the last attempt to be -window*2 to avoid immediately
	// giving another login failure.
	attr[UserAttemptTime] = time.Now().UTC().Add(-l.window * 2)
	attr[UserAttemptNumber] = 0
	attr[UserLocked] = false

	return storer.Put(key, attr)
}
