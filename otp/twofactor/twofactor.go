// Package otp allows authentication via one time passwords
package otp

import "github.com/volatiletech/authboss"

// Authenticator is a type that implements the basic functionality
// to be able to authenticate via a one time password.
type Authenticator interface {
	// Initialize by giving the user a way to enter the first otp
	Setup(User)
	// Verify the otp for the user
	Verify(User, string)
	// Remove otp for the user, requires the user be fully authenticated
	// and have authenticated with a one time password.
	Remove(User, string)
}

// User interface
type User interface {
	authboss.User

	GetEmail() string
	PutEmail(string)

	// GetRecoveryCodes retrieves a CSV string of bcrypt'd recovery codes
	GetRecoveryCodes() string
	// PutRecoveryCodes uses a single string to store many bcrypt'd recovery codes
	PutRecoveryCodes(codes string)
}
