package authboss

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

	// Save persists the user in the database
	Save(ctx context.Context, user User) error
}

// User has functions for each piece of data it requires.
// Data should not be persisted on each function call.
// User has a PID (primary ID) that is used on the site as
// a single unique identifier to any given user (very typically e-mail
// or username).
type User interface {
	GetPID(ctx context.Context) (pid string, err error)
	PutPID(ctx context.Context, pid string) error
}

// AuthableUser is identified by a password
type AuthableUser interface {
	User

	GetPassword(ctx context.Context) (password string, err error)
	PutPassword(ctx context.Context, password string) error
}

// ConfirmableUser can be in a state of confirmed or not
type ConfirmableUser interface {
	User

	GetConfirmed(ctx context.Context) (confirmed bool, err error)
	GetConfirmToken(ctx context.Context) (token string, err error)

	PutConfirmed(ctx context.Context, confirmed bool) error
	PutConfirmToken(ctx context.Context, token string) error
}

// ArbitraryUser allows arbitrary data from the web form through. You should
// definitely only pull the keys you want from the map, since this is unfiltered
// input from a web request and is an attack vector.
type ArbitraryUser interface {
	User

	// GetArbitrary is used only to display the arbitrary data back to the user
	// when the form is reset.
	GetArbitrary(ctx context.Context) (arbitrary map[string]string, err error)
	// PutArbitrary allows arbitrary fields defined by the authboss library
	// consumer to add fields to the user registration piece.
	PutArbitrary(ctx context.Context, arbitrary map[string]string) error
}

// OAuth2User allows reading and writing values relating to OAuth2
type OAuth2User interface {
	User

	// IsOAuth2User checks to see if a user was registered in the site as an
	// oauth2 user.
	IsOAuth2User(ctx context.Context) (bool, error)

	GetUID(ctx context.Context) (uid string, err error)
	GetProvider(ctx context.Context) (provider string, err error)
	GetToken(ctx context.Context) (token string, err error)
	GetRefreshToken(ctx context.Context) (refreshToken string, err error)
	GetExpiry(ctx context.Context) (expiry time.Duration, err error)

	PutUID(ctx context.Context, uid string) error
	PutProvider(ctx context.Context, provider string) error
	PutToken(ctx context.Context, token string) error
	PutRefreshToken(ctx context.Context, refreshToken string) error
	PutExpiry(ctx context.Context, expiry time.Duration) error
}
