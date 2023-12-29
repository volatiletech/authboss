package authboss

import (
	"context"
)

type Localizer interface {
	// Get the translation for the given text in the given context.
	// If no translation is found, an empty string should be returned.
	Localizef(ctx context.Context, txt string, args ...any) string
}

// Translation constants
const (
	TxtSuccess = "success"

	// Used in the auth module
	TxtInvalidCredentials = "Invalid Credentials"
	TxtAuthFailed         = "Please login"

	// Used in the register module
	TxtUserAlreadyExists     = "User already exists"
	TxtRegisteredAndLoggedIn = "Account successfully created, you are now logged in"

	// Used in the confirm module
	TxtConfirmYourAccount  = "Please verify your account, an e-mail has been sent to you."
	TxtAccountNotConfirmed = "Your account has not been confirmed, please check your e-mail."
	TxtInvalidConfirmToken = "Your confirmation token is invalid."
	TxtConfrimationSuccess = "You have successfully confirmed your account."
	TxtConfirmEmailSubject = "Confirm New Account"

	// Used in the lock module
	TxtLocked = "Your account has been locked, please contact the administrator."

	// Used in the logout module
	TxtLoggedOut = "You have been logged out"

	// Used in the oauth2 module
	TxtOAuth2LoginOK    = "Logged in successfully with %s."
	TxtOAuth2LoginNotOK = "%s login cancelled or failed"

	// Used in the recover module
	TxtRecoverInitiateSuccessFlash = "An email has been sent to you with further instructions on how to reset your password."
	TxtPasswordResetEmailSubject   = "Password Reset"
	TxtRecoverSuccessMsg           = "Successfully updated password"
	TxtRecoverAndLoginSuccessMsg   = "Successfully updated password and logged in"

	// Used in the otp module
	TxtTooManyOTPs = "You cannot have more than %d one time passwords"

	// Used in the 2fa module
	TxtEmailVerifyTriggered        = "An e-mail has been sent to confirm 2FA activation"
	TxtEmailVerifySubject          = "Add 2FA to Account"
	TxtInvalid2FAVerificationToken = "Invalid 2FA email verification token"
	Txt2FAAuthorizationRequired    = "You must first authorize adding 2fa by e-mail"
	TxtInvalid2FACode              = "2FA code was invalid"
	TxtRepeated2FACode             = "2FA code was previously used"
	TxtTOTP2FANotActive            = "TOTP 2FA is not active"
	TxtSMSNumberRequired           = "You must provide a phone number"
	TxtSMSWaitToResend             = "Please wait a few moments before resending the SMS code"
)
