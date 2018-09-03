package authboss

import (
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config holds all the configuration for both authboss and it's modules.
type Config struct {
	Paths struct {
		// Mount is the path to mount authboss's routes at (eg /auth).
		Mount string
		// NotAuthorized is the default URL to kick users back to when
		// they attempt an action that requires them to be logged in and they're not auth'd
		NotAuthorized string

		// AuthLoginOK is the redirect path after a successful authentication.
		AuthLoginOK string

		// ConfirmOK once a user has confirmed their account, where should they go
		ConfirmOK string
		// ConfirmNotOK is used by the middleware, when a user is still supposed to
		// confirm their account, this is where they should be redirected to.
		ConfirmNotOK string

		// LockNotOK is a path to go to when the user fails
		LockNotOK string

		// LogoutOK is the redirect path after a log out.
		LogoutOK string

		// OAuth2LoginOK is the redirect path after a successful oauth2 login
		OAuth2LoginOK string
		// OAuth2LoginNotOK is the redirect path after an unsuccessful oauth2 login
		OAuth2LoginNotOK string

		// RecoverOK is the redirect path after a successful recovery of a password.
		RecoverOK string

		// RegisterOK is the redirect path after a successful registration.
		RegisterOK string

		// RootURL is the scheme+host+port of the web application (eg https://www.happiness.com:8080) for url generation. No trailing slash.
		RootURL string
	}

	Modules struct {
		// BCryptCost is the cost of the bcrypt password hashing function.
		BCryptCost int

		// ExpireAfter controls the time an account is idle before being logged out
		// by the ExpireMiddleware.
		ExpireAfter time.Duration

		// LockAfter this many tries.
		LockAfter int
		// LockWindow is the waiting time before the number of attemps are reset.
		LockWindow time.Duration
		// LockDuration is how long an account is locked for.
		LockDuration time.Duration

		// LogoutMethod is the method the logout route should use (default should be DELETE)
		LogoutMethod string

		// RegisterPreserveFields are fields used with registration that are to be rendered when
		// post fails in a normal way (for example validation errors), they will be passed
		// back in the data of the response under the key DataPreserve which will be a map[string]string.
		//
		// All fields that are to be preserved must be able to be returned by the ArbitraryValuer.GetValues()
		//
		// This means in order to have a field named "address" you would need to have that returned by
		// the ArbitraryValuer.GetValues() method and then it would be available to be whitelisted by this
		// configuration variable.
		RegisterPreserveFields []string

		// RecoverTokenDuration controls how long a token sent via email for password
		// recovery is valid for.
		RecoverTokenDuration time.Duration
		// RecoverLoginAfterRecovery says for the recovery module after a user has successfully
		// recovered the password, are they simply logged in, or are they redirected to
		// the login page with an "updated password" message.
		RecoverLoginAfterRecovery bool

		// OAuth2Providers lists all providers that can be used. See
		// OAuthProvider documentation for more details.
		OAuth2Providers map[string]OAuth2Provider

		// TOTP2FAIssuer is the issuer that appears in the url when scanning a qr code
		// for google authenticator.
		TOTP2FAIssuer string

		// RoutesRedirectOnUnauthed controls whether or not a user is redirected or given
		// a 404 when they are unauthenticated and attempting to access a route that's
		// login-protected inside Authboss itself. The otp/twofactor modules all use
		// authboss.Middleware to protect their routes and this is the
		// redirectToLogin parameter in that middleware that they pass through.
		RoutesRedirectOnUnauthed bool
	}

	Mail struct {
		// From is the email address authboss e-mails come from.
		From string
		// FromName is the name authboss e-mails come from.
		FromName string
		// SubjectPrefix is used to add something to the front of the authboss
		// email subjects.
		SubjectPrefix string
	}

	Storage struct {
		// Storer is the interface through which Authboss accesses the web apps database
		// for user operations.
		Server ServerStorer

		// CookieState must be defined to provide an interface capapable of
		// storing cookies for the given response, and reading them from the request.
		CookieState ClientStateReadWriter
		// SessionState must be defined to provide an interface capable of
		// storing session-only values for the given response, and reading them
		// from the request.
		SessionState ClientStateReadWriter
	}

	Core struct {
		// Router is the entity that controls all routing to authboss routes
		// modules will register their routes with it.
		Router Router

		// ErrorHandler wraps http requests with centralized error handling.
		ErrorHandler ErrorHandler

		// Responder takes a generic response from a controller and prepares
		// the response, uses a renderer to create the body, and replies to the
		// http request.
		Responder HTTPResponder

		// Redirector can redirect a response, similar to Responder but responsible
		// only for redirection.
		Redirector HTTPRedirector

		// BodyReader reads validatable data from the body of a request to be able
		// to get data from the user's client.
		BodyReader BodyReader

		// ViewRenderer loads the templates for the application.
		ViewRenderer Renderer
		// MailRenderer loads the templates for mail. If this is nil, it will
		// fall back to using the Renderer created from the ViewLoader instead.
		MailRenderer Renderer

		// Mailer is the mailer being used to send e-mails out via smtp
		Mailer Mailer

		// Logger implies just a few log levels for use, can optionally
		// also implement the ContextLogger to be able to upgrade to a
		// request specific logger.
		Logger Logger
	}
}

// Defaults sets the configuration's default values.
func (c *Config) Defaults() {
	c.Paths.Mount = "/auth"
	c.Paths.NotAuthorized = "/"
	c.Paths.AuthLoginOK = "/"
	c.Paths.ConfirmOK = "/"
	c.Paths.ConfirmNotOK = "/"
	c.Paths.LockNotOK = "/"
	c.Paths.LogoutOK = "/"
	c.Paths.OAuth2LoginOK = "/"
	c.Paths.OAuth2LoginNotOK = "/"
	c.Paths.RecoverOK = "/"
	c.Paths.RegisterOK = "/"
	c.Paths.RootURL = "http://localhost:8080"

	c.Modules.BCryptCost = bcrypt.DefaultCost
	c.Modules.ExpireAfter = time.Hour
	c.Modules.LockAfter = 3
	c.Modules.LockWindow = 5 * time.Minute
	c.Modules.LockDuration = 12 * time.Hour
	c.Modules.LogoutMethod = "DELETE"
	c.Modules.RecoverLoginAfterRecovery = false
	c.Modules.RecoverTokenDuration = 24 * time.Hour
}
