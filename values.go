package authboss

import (
	"fmt"
	"net/http"
)

// BodyReader reads data from the request
// and returns it in an abstract form.
// Typically used to decode JSON responses
// or Url Encoded request bodies.
//
// The first parameter is the page that this request
// was made on so we can tell what kind of JSON object
// or form was present as well as create the proper
// validation mechanisms.
//
// A typical example of this is taking the request
// and turning it into a JSON struct that knows how
// to validate itself and return certain fields.
type BodyReader interface {
	Read(page string, r *http.Request) (Validator, error)
}

// UserValuer allows us to pull out the PID and Password from the request.
type UserValuer interface {
	Validator

	GetPID() string
	GetPassword() string
}

// ConfirmValuer allows us to pull out the token from the request
type ConfirmValuer interface {
	Validator

	GetToken() string
}

// RecoverStartValuer provides the PID entered by the user.
type RecoverStartValuer interface {
	Validator

	GetPID() string
}

// RecoverMiddleValuer provides the token that the user submitted
// via their link.
type RecoverMiddleValuer interface {
	Validator

	GetToken() string
}

// RecoverEndValuer is used to get data back from the final
// page of password recovery, the user will provide a password
// and it must be accompanied by the token to authorize the changing
// of that password. Contrary to the RecoverValuer, this should
// have validation errors for bad tokens.
type RecoverEndValuer interface {
	Validator

	GetPassword() string
	GetToken() string
}

// RememberValuer allows auth/oauth2 to pass along the remember
// bool from the user to the remember module unobtrusively.
type RememberValuer interface {
	// Intentionally omitting validator

	// GetShouldRemember is the checkbox or what have you that
	// tells the remember module if it should remember that user's
	// authentication or not.
	GetShouldRemember() bool
}

// ArbitraryValuer provides the "rest" of the fields
// that aren't strictly needed for anything in particular,
// address, secondary e-mail, etc.
//
// There are two important notes about this interface:
//
// 1. That this is composed with Validator, as these fields
// should both be validated and culled of invalid pieces
// as they will be passed into ArbitraryUser.PutArbitrary()
//
// 2. These values will also be culled according to the RegisterPreserveFields
// whitelist and sent back in the data under the key DataPreserve.
type ArbitraryValuer interface {
	Validator

	GetValues() map[string]string
}

// MustHaveUserValues upgrades a validatable set of values
// to ones specific to an authenticating user.
func MustHaveUserValues(v Validator) UserValuer {
	if u, ok := v.(UserValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to UserValuer: %T", v))
}

// MustHaveConfirmValues upgrades a validatable set of values
// to ones specific to a user that needs to be confirmed.
func MustHaveConfirmValues(v Validator) ConfirmValuer {
	if u, ok := v.(ConfirmValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to ConfirmValuer: %T", v))
}

// MustHaveRecoverStartValues upgrades a validatable set of values
// to ones specific to a user that needs to be recovered.
func MustHaveRecoverStartValues(v Validator) RecoverStartValuer {
	if u, ok := v.(RecoverStartValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to RecoverStartValuer: %T", v))
}

// MustHaveRecoverMiddleValues upgrades a validatable set of values
// to ones specific to a user that's attempting to recover.
func MustHaveRecoverMiddleValues(v Validator) RecoverMiddleValuer {
	if u, ok := v.(RecoverMiddleValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to RecoverMiddleValuer: %T", v))
}

// MustHaveRecoverEndValues upgrades a validatable set of values
// to ones specific to a user that needs to be recovered.
func MustHaveRecoverEndValues(v Validator) RecoverEndValuer {
	if u, ok := v.(RecoverEndValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to RecoverEndValuer: %T", v))
}
