package authboss

import (
	"fmt"
	"time"
)

// User has functions for each piece of data it requires.
// Data should not be persisted on each function call.
// User has a PID (primary ID) that is used on the site as
// a single unique identifier to any given user (very typically e-mail
// or username).
//
// User interfaces return no errors or bools to signal that a value was
// not present. Instead 0-value = null = not present, this puts the onus
// on Authboss code to check for this.
type User interface {
	GetPID() (pid string)
	PutPID(pid string)
}

// AuthableUser is identified by a password
type AuthableUser interface {
	User

	GetPassword() (password string)
	PutPassword(password string)
}

// ConfirmableUser can be in a state of confirmed or not
type ConfirmableUser interface {
	User

	GetConfirmed() (confirmed bool)
	GetConfirmToken() (token string)
	GetEmail() (email string)

	PutConfirmed(confirmed bool)
	PutConfirmToken(token string)
	PutEmail(email string)
}

// LockableUser is a user that can be locked
type LockableUser interface {
	User

	GetAttemptCount() (attempts int)
	GetLastAttempt() (last time.Time)
	GetLocked() (locked time.Time)

	PutAttemptCount(attempts int)
	PutLastAttempt(last time.Time)
	PutLocked(locked time.Time)
}

// RecoverableUser is a user that can be recovered via e-mail
type RecoverableUser interface {
	AuthableUser

	GetEmail() (email string)
	GetRecoverToken() (token string)
	GetRecoverExpiry() (expiry time.Time)

	PutEmail(email string)
	PutRecoverToken(token string)
	PutRecoverExpiry(expiry time.Time)
}

// ArbitraryUser allows arbitrary data from the web form through. You should
// definitely only pull the keys you want from the map, since this is unfiltered
// input from a web request and is an attack vector.
type ArbitraryUser interface {
	User

	// GetArbitrary is used only to display the arbitrary data back to the user
	// when the form is reset.
	GetArbitrary() (arbitrary map[string]string)
	// PutArbitrary allows arbitrary fields defined by the authboss library
	// consumer to add fields to the user registration piece.
	PutArbitrary(arbitrary map[string]string)
}

// OAuth2User allows reading and writing values relating to OAuth2
type OAuth2User interface {
	User

	// IsOAuth2User checks to see if a user was registered in the site as an
	// oauth2 user.
	IsOAuth2User() bool

	GetUID() (uid string)
	GetProvider() (provider string)
	GetToken() (token string)
	GetRefreshToken() (refreshToken string)
	GetExpiry() (expiry time.Duration)

	PutUID(uid string)
	PutProvider(provider string)
	PutToken(token string)
	PutRefreshToken(refreshToken string)
	PutExpiry(expiry time.Duration)
}

// MustBeAuthable forces an upgrade to an AuthableUser or panic.
func MustBeAuthable(u User) AuthableUser {
	if au, ok := u.(AuthableUser); ok {
		return au
	}
	panic(fmt.Sprintf("could not upgrade user to an authable user, type: %T", u))
}

// MustBeConfirmable forces an upgrade to a ConfirmableUser or panic.
func MustBeConfirmable(u User) ConfirmableUser {
	if cu, ok := u.(ConfirmableUser); ok {
		return cu
	}
	panic(fmt.Sprintf("could not upgrade user to a confirmable user, type: %T", u))
}

// MustBeLockable forces an upgrade to a LockableUser or panic.
func MustBeLockable(u User) LockableUser {
	if lu, ok := u.(LockableUser); ok {
		return lu
	}
	panic(fmt.Sprintf("could not upgrade user to a lockable user, given type: %T", u))
}

// MustBeRecoverable forces an upgrade to a RecoverableUser or panic.
func MustBeRecoverable(u User) RecoverableUser {
	if lu, ok := u.(RecoverableUser); ok {
		return lu
	}
	panic(fmt.Sprintf("could not upgrade user to a recoverable user, given type: %T", u))
}
