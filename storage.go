package authboss

// A concious decision was made to put all storer
// and user types into this file despite them truly
// belonging to outside modules. The reason for this
// is because documentation-wise, it was previously
// difficult to find what you had to implement or even
// what you could implement.

import (
	"context"
	"time"

	"github.com/pkg/errors"
)

// Data store constants for attribute names.
const (
	StoreEmail    = "email"
	StoreUsername = "username"
	StorePassword = "password"
)

// Data store constants for OAuth2 attribute names.
const (
	StoreOAuth2UID      = "oauth2_uid"
	StoreOAuth2Provider = "oauth2_provider"
	StoreOAuth2Token    = "oauth2_token"
	StoreOAuth2Refresh  = "oauth2_refresh"
	StoreOAuth2Expiry   = "oauth2_expiry"
)

var (
	// ErrUserNotFound should be returned from Get when the record is not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrTokenNotFound should be returned from UseToken when the record is not found.
	ErrTokenNotFound = errors.New("token not found")
	// ErrUserFound should be returned from Create (see ConfirmUser) when the primaryID
	// of the record is found.
	ErrUserFound = errors.New("user found")
)

// ServerStorer represents the data store that's capable of loading users
// and giving them a context with which to store themselves.
type ServerStorer interface {
	// Load will look up the user based on the passed the PrimaryID
	Load(ctx context.Context, key string) (User, error)

	// Save persists the user in the database, this should never
	// create a user and instead return ErrUserNotFound if the user
	// does not exist.
	Save(ctx context.Context, user User) error
}

// CreatingServerStorer is used for creating new users
// like when Registration is being done.
type CreatingServerStorer interface {
	// New creates a blank user, it is not yet persisted in the database
	// but is just for storing data
	New(ctx context.Context) User
	// Create the user in storage, it should not overwrite a user
	// and should return ErrUserFound if it currently exists.
	Create(ctx context.Context, user User) error
}

// EnsureCanCreate makes sure the server storer supports create operations
func EnsureCanCreate(storer ServerStorer) CreatingServerStorer {
	s, ok := storer.(CreatingServerStorer)
	if !ok {
		panic("could not upgrade serverstorer to creatingserverstorer, check your struct")
	}

	return s
}

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

// MustBeAuthable forces an upgrade conversion to Authable
// or will panic.
func MustBeAuthable(u User) AuthableUser {
	if au, ok := u.(AuthableUser); ok {
		return au
	}
	panic("could not upgrade user to an authable user, check your user struct")
}
