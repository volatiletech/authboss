package authboss

// A concious decision was made to put all storer
// and user types into this file despite them truly
// belonging to outside modules. The reason for this
// is because documentation-wise, it was previously
// difficult to find what you had to implement or even
// what you could implement.

import (
	"context"

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

// ConfirmingServerStorer can find a user by a confirm token
type ConfirmingServerStorer interface {
	Load(ctx context.Context, token string) (User, error)
}

// EnsureCanCreate makes sure the server storer supports create operations
func EnsureCanCreate(storer ServerStorer) CreatingServerStorer {
	s, ok := storer.(CreatingServerStorer)
	if !ok {
		panic("could not upgrade serverstorer to creatingserverstorer, check your struct")
	}

	return s
}

// EnsureCanConfirm makes sure the server storer supports confirm-lookup operations
func EnsureCanConfirm(storer ServerStorer) ConfirmingServerStorer {
	s, ok := storer.(ConfirmingServerStorer)
	if !ok {
		panic("could not upgrade serverstorer to confirmingserverstorer, check your struct")
	}

	return s
}
