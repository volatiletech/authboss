// Package lock implements user locking after N bad sign-in attempts.
package lock

import (
	"errors"
	"fmt"
	"time"

	"gopkg.in/authboss.v0"
)

const (
	StoreAttemptNumber = "attempt_number"
	StoreAttemptTime   = "attempt_time"
	StoreLocked        = "locked"
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
		StoreLocked:        authboss.Bool,
	}
}

// BeforeAuth ensures the account is not locked.
func (l *Lock) BeforeAuth(ctx *authboss.Context) error {
	if ctx.User == nil {
		return errors.New("lock: user not loaded in before auth callback")
	}

	if intf, ok := ctx.User[StoreLocked]; ok {
		if locked, ok := intf.(bool); ok && locked {
			return ErrLocked
		}
	}

	return nil
}

// AfterAuth resets the attempt number field.
func (l *Lock) AfterAuth(ctx *authboss.Context) {
	if ctx.User == nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "lock: user not loaded in after auth callback")
		return
	}

	ctx.User[StoreAttemptNumber] = 0
	ctx.User[StoreAttemptTime] = time.Now().UTC()

	if err := ctx.SaveUser(); err != nil {
		fmt.Fprintf(authboss.Cfg.LogWriter, "lock: saving user failed %v", err)
	}
}

// AfterAuthFail adjusts the attempt number and time.
func (l *Lock) AfterAuthFail(ctx *authboss.Context) {
	if ctx.User == nil {
		return
	}

	lastAttempt := time.Now().UTC()
	if attemptTimeIntf, ok := ctx.User[StoreAttemptTime]; ok {
		if attemptTime, ok := attemptTimeIntf.(time.Time); ok {
			lastAttempt = attemptTime
		}
	}

	nAttempts := 0
	if attemptsIntf, ok := ctx.User[StoreAttemptNumber]; ok {
		if attempts, ok := attemptsIntf.(int); ok {
			nAttempts = attempts
		}
	}

	nAttempts++

	if time.Now().UTC().Sub(lastAttempt) <= authboss.Cfg.LockWindow {
		if nAttempts >= authboss.Cfg.LockAfter {
			ctx.User[StoreLocked] = true
		}

		ctx.User[StoreAttemptNumber] = nAttempts
	} else {
		ctx.User[StoreAttemptNumber] = 0
	}
	ctx.User[StoreAttemptTime] = time.Now().UTC()

	if err := ctx.SaveUser(); err != nil {
		fmt.Fprintf(authboss.Cfg.LogWriter, "lock: saving user failed %v", err)
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

	attr[StoreLocked] = true

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
	attr[StoreAttemptTime] = time.Now().UTC().Add(-authboss.Cfg.LockWindow * 2)
	attr[StoreAttemptNumber] = 0
	attr[StoreLocked] = false

	return storer.Put(key, attr)
}
