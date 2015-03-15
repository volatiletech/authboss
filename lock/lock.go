// Package lock implements user locking after N bad sign-in attempts.
package lock

import (
	"errors"
	"time"

	"gopkg.in/authboss.v0"
)

const (
	StoreAttemptNumber = "attempt_number"
	StoreAttemptTime   = "attempt_time"
	StoreLocked        = "locked"
)

var (
	errUserMissing = errors.New("lock: user not loaded in BeforeAuth callback")
)

func init() {
	authboss.RegisterModule("lock", &Lock{})
}

type Lock struct {
}

func (l *Lock) Initialize() error {
	if authboss.Cfg.Storer == nil {
		return errors.New("lock: Need a Storer.")
	}

	// Events
	authboss.Cfg.Callbacks.Before(authboss.EventGet, l.BeforeAuth)
	authboss.Cfg.Callbacks.Before(authboss.EventAuth, l.BeforeAuth)
	authboss.Cfg.Callbacks.After(authboss.EventAuth, l.AfterAuth)
	authboss.Cfg.Callbacks.After(authboss.EventAuthFail, l.AfterAuthFail)

	return nil
}

func (l *Lock) Routes() authboss.RouteTable {
	return nil
}

func (l *Lock) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		StoreAttemptNumber: authboss.Integer,
		StoreAttemptTime:   authboss.DateTime,
		StoreLocked:        authboss.DateTime,
	}
}

// BeforeAuth ensures the account is not locked.
func (l *Lock) BeforeAuth(ctx *authboss.Context) (authboss.Interrupt, error) {
	if ctx.User == nil {
		return authboss.InterruptNone, errUserMissing
	}

	if locked, ok := ctx.User.DateTime(StoreLocked); ok && locked.After(time.Now().UTC()) {
		return authboss.InterruptAccountLocked, nil
	}

	return authboss.InterruptNone, nil
}

// AfterAuth resets the attempt number field.
func (l *Lock) AfterAuth(ctx *authboss.Context) error {
	if ctx.User == nil {
		return errUserMissing
	}

	ctx.User[StoreAttemptNumber] = int64(0)
	ctx.User[StoreAttemptTime] = time.Now().UTC()

	if err := ctx.SaveUser(); err != nil {
		return err
	}

	return nil
}

// AfterAuthFail adjusts the attempt number and time.
func (l *Lock) AfterAuthFail(ctx *authboss.Context) error {
	if ctx.User == nil {
		return errUserMissing
	}

	lastAttempt := time.Now().UTC()
	if attemptTime, ok := ctx.User.DateTime(StoreAttemptTime); ok {
		lastAttempt = attemptTime
	}

	var nAttempts int64
	if attempts, ok := ctx.User.Int64(StoreAttemptNumber); ok {
		nAttempts = attempts
	}

	nAttempts++

	if time.Now().UTC().Sub(lastAttempt) <= authboss.Cfg.LockWindow {
		if nAttempts >= int64(authboss.Cfg.LockAfter) {
			ctx.User[StoreLocked] = time.Now().UTC().Add(authboss.Cfg.LockDuration)
		}

		ctx.User[StoreAttemptNumber] = nAttempts
	} else {
		ctx.User[StoreAttemptNumber] = int64(0)
	}
	ctx.User[StoreAttemptTime] = time.Now().UTC()

	if err := ctx.SaveUser(); err != nil {
		return err
	}

	return nil
}

// Lock a user manually.
func (l *Lock) Lock(key string) error {
	user, err := authboss.Cfg.Storer.Get(key)
	if err != nil {
		return err
	}

	attr := authboss.Unbind(user)
	if err != nil {
		return err
	}

	attr[StoreLocked] = time.Now().UTC().Add(authboss.Cfg.LockDuration)

	return authboss.Cfg.Storer.Put(key, attr)
}

// Unlock a user that was locked by this module.
func (l *Lock) Unlock(key string) error {
	user, err := authboss.Cfg.Storer.Get(key)
	if err != nil {
		return err
	}

	attr := authboss.Unbind(user)
	if err != nil {
		return err
	}

	// Set the last attempt to be -window*2 to avoid immediately
	// giving another login failure.
	attr[StoreAttemptTime] = time.Now().UTC().Add(-authboss.Cfg.LockWindow * 2)
	attr[StoreAttemptNumber] = int64(0)
	attr[StoreLocked] = time.Now().UTC().Add(-authboss.Cfg.LockDuration)

	return authboss.Cfg.Storer.Put(key, attr)
}
