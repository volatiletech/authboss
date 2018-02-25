package authboss

import "time"

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

	PutConfirmed(confirmed bool)
	PutConfirmToken(token string)
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

// MustBeAuthable forces an upgrade to an Authable user or panic.
func MustBeAuthable(u User) AuthableUser {
	if au, ok := u.(AuthableUser); ok {
		return au
	}
	panic("could not upgrade user to an authable user, check your user struct")
}

// MustBeConfirmable forces an upgrade to a Confirmable user or panic.
func MustBeConfirmable(u User) ConfirmableUser {
	if cu, ok := u.(ConfirmableUser); ok {
		return cu
	}
	panic("could not upgrade user to a confirmable user, check your user struct")
}
