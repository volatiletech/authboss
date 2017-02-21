package authboss

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"
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
	ErrUserNotFound = errors.New("User not found")
	// ErrTokenNotFound should be returned from UseToken when the record is not found.
	ErrTokenNotFound = errors.New("Token not found")
	// ErrUserFound should be returned from Create when the primaryID of the record is found.
	ErrUserFound = errors.New("User found")
)

// StoreLoader represents the data store that's capable of loading users
// and giving them a context with which to store themselves.
type StoreLoader interface {
	// Load will be passed the PrimaryID and return pre-loaded storer (meaning
	// Storer.Load will not be called)
	Load(ctx context.Context, key string) (Storer, error)
}

// Storer represents a user that also knows how to put himself into the db.
// It has functions for each piece of data it requires.
// Note that you should only persist data once Save() has been called.
type Storer interface {
	PutEmail(ctx context.Context, email string) error
	PutUsername(ctx context.Context, username string) error
	PutPassword(ctx context.Context, password string) error

	GetEmail(ctx context.Context) (email string, err error)
	GetUsername(ctx context.Context) (username string, err error)
	GetPassword(ctx context.Context) (password string, err error)

	// Save the state.
	Save(ctx context.Context) error

	// Load the state based on the properties that have been given (typically
	// an e-mail/username).
	Load(ctx context.Context) error
}

type ArbitraryStorer interface {
	Storer

	// PutArbitrary allows arbitrary fields defined by the authboss library
	// consumer to add fields to the user registration piece.
	PutArbitrary(ctx context.Context, arbitrary map[string]string) error
	// GetArbitrary is used only to display the arbitrary data back to the user
	// when the form is reset.
	GetArbitrary(ctx context.Context) (arbitrary map[string]string, err error)
}

// OAuth2Storer allows reading and writing values
type OAuth2Storer interface {
	Storer

	PutUID(ctx context.Context, uid string) error
	PutProvider(ctx context.Context, provider string) error
	PutToken(ctx context.Context, token string) error
	PutRefreshToken(ctx context.Context, refreshToken string) error
	PutExpiry(ctx context.Context, expiry time.Duration) error

	GetUID(ctx context.Context) (uid string, err error)
	GetProvider(ctx context.Context) (provider string, err error)
	GetToken(ctx context.Context) (token string, err error)
	GetRefreshToken(ctx context.Context) (refreshToken string, err error)
	GetExpiry(ctx context.Context) (expiry time.Duration, err error)
}

// DataType represents the various types that clients must be able to store.
type DataType int

// DataType constants
const (
	Integer DataType = iota
	String
	Bool
	DateTime
)

var (
	dateTimeType = reflect.TypeOf(time.Time{})
)

// String returns a string for the DataType representation.
func (d DataType) String() string {
	switch d {
	case Integer:
		return "Integer"
	case String:
		return "String"
	case Bool:
		return "Bool"
	case DateTime:
		return "DateTime"
	}
	return ""
}

func camelToUnder(in string) string {
	out := bytes.Buffer{}
	for i := 0; i < len(in); i++ {
		chr := in[i]
		if chr >= 'A' && chr <= 'Z' {
			if i > 0 {
				out.WriteByte('_')
			}
			out.WriteByte(chr + 'a' - 'A')
		} else {
			out.WriteByte(chr)
		}
	}
	return out.String()
}

func underToCamel(in string) string {
	out := bytes.Buffer{}
	for i := 0; i < len(in); i++ {
		chr := in[i]

		if first := i == 0; first || chr == '_' {
			if !first {
				i++
			}
			out.WriteByte(in[i] - 'a' + 'A')
		} else {
			out.WriteByte(chr)
		}
	}
	return out.String()
}
