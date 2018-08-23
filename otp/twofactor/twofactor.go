// Package twofactor allows authentication via one time passwords
package twofactor

import "github.com/volatiletech/authboss"

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

// TOTPUser interface
type TOTPUser interface {
	User

	GetTOTPSecretKey() string
	PutTOTPSecretKey(string)
}

// SMSUser interface
type SMSUser interface {
	User

	GetPhoneNumber() string
	PutPhoneNumber(string)
}

// SMSPhoneGetter retrieves an initial phone number
// to use as the SMS 2fa number.
type SMSPhoneGetter interface {
	GetInitialPhoneNumber() string
}

/*
GET  /2fa/setup/{sms,totp}
POST /2fa/setup/{sms,totp}
- sms:
	- send a 6-8 digit code to the users's phone number
	- save this temporary code in the session for the next API call

- totp:
	- generate a private key and store it, temporarily in session

GET /2fa/qr/{sms,totp}
- totp:
	- send back an image of the secret key that's in the session, fallback to the database

GET  /2fa/confirm/{sms,totp}
POST /2fa/confirm/{sms,totp}
- totp:
	- post the 2fa code, this finalizes the secret key in the session by storing it into the database
	- generate and save 10 recovery codes, return in data
- sms:
	- post the sms code delivered to your phone, to finalize that sms phone number
	- generate and save 10 recovery codes, return in data

GET /2fa/remove/{sms,totp}
- totp:
	- ask for a code
- sms:
	- send code to fone

POST /2fa/remove/{sms,totp}
- totp:
	- if code matches, remove 2fa
- sms:
	- if code matches, remove 2fa

GET /2fa/recovery DOES NOT EXIST LOL, WAT 2 SHO?
	- show recovery codes
POST /2fa/recovery/regenerate
	- regenerate 10 recovery codes and display them
*/

/*

// Authenticator is a type that implements the basic functionality
// to be able to authenticate via a one time password as a second factor.
type Authenticator interface {
	// Setup a secret and generate a code from it so that the 2fa method can be attached
	// to the user if they correctly pass back the code. The secret itself
	// is stored in the session and will be passed back to be stored on the
	// user object in the enable step.
	Setup(User) (code string, secret string, err error)

	// Enable 2fa on the user, requires the code produced
	// by the secret and the secret itself that will have come
	// from Setup.
	Enable(user User, code string, secret string) error

	// Teardown prepares to disable 2fa on the user.
	Teardown(User) (code string, err error)

	// Disable 2fa on the user, requires a code sent by teardown
	// or in some cases that the user will already know.
	Disable(user User, code string, secret string) error

	// IsActive checks if this authenticator is active on the current user
	// This is to ensure that only one authentication method is active at a time
	IsActive(User) bool
}

// Authenticator is the basic functionality for a second factor authenticator
type Authenticator interface {
	Secret(User) (secret string, err error)
	Code(user User, secret string) (code string, err error)
	Verify(user User, code, secret string) error

	Enabled(User) bool
	Enable(User) error
	Disable(User) error
}

// QRAuthenticator is able to provide a QR code to represent it's secrets
type QRAuthenticator interface {
	// Returns a file as []byte and a mime type
	QRCode(User) ([]byte, string)
}

*/
