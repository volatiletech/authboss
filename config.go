package authboss

import (
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Cfg is the singleton instance of Config
var Cfg = NewConfig()

// Config holds all the configuration for both authboss and it's modules.
type Config struct {
	// MountPath is the path to mount authboss's routes at (eg /auth).
	MountPath string
	// ViewsPath is the path to search for overridden templates.
	ViewsPath string
	// RootURL is the scheme+host+port of the web application (eg https://www.happiness.com:8080) for url generation.  No trailing slash.
	RootURL string
	// BCryptCost is the cost of the bcrypt password hashing function.
	BCryptCost int

	// PrimaryID is the primary identifier of the user. Set to one of:
	// authboss.StoreEmail, authboss.StoreUsername (StoreEmail is default)
	PrimaryID string

	// Layout that all authboss views will be inserted into.
	Layout *template.Template
	// LayoutHTMLEmail is for emails going out in HTML form, authbosses e-mail templates
	// will be inserted into this layout.
	LayoutHTMLEmail *template.Template
	// LayoutTextEmail is for emails going out in text form, authbosses e-mail templates
	// will be inserted into this layout.
	LayoutTextEmail *template.Template
	// LayoutDataMaker is a function that can provide authboss with the layout's
	// template data. It will be merged with the data being provided for the current
	// view in order to render the templates.
	LayoutDataMaker ViewDataMaker

	// OAuth2Providers lists all providers that can be used. See
	// OAuthProvider documentation for more details.
	OAuth2Providers map[string]OAuth2Provider

	// ErrorHandler handles would be 500 errors.
	ErrorHandler http.Handler
	// BadRequestHandler handles would be 400 errors.
	BadRequestHandler http.Handler
	// NotFoundHandler handles would be 404 errors.
	NotFoundHandler http.Handler

	// AuthLoginOKPath is the redirect path after a successful authentication.
	AuthLoginOKPath string
	// AuthLoginFailPath is the redirect path after a failed authentication.
	AuthLoginFailPath string
	// AuthLogoutOKPath is the redirect path after a log out.
	AuthLogoutOKPath string

	// RecoverOKPath is the redirect path after a successful recovery of a password.
	RecoverOKPath string
	// RecoverTokenDuration controls how long a token sent via email for password
	// recovery is valid for.
	RecoverTokenDuration time.Duration

	// RegisterOKPath is the redirect path after a successful registration.
	RegisterOKPath string

	// Policies control validation of form fields and are automatically run
	// against form posts that include the fields.
	Policies []Validator
	// ConfirmFields are fields that are supposed to be submitted with confirmation
	// fields alongside them, passwords, emails etc.
	ConfirmFields []string

	// ExpireAfter controls the time an account is idle before being logged out
	// by the ExpireMiddleware.
	ExpireAfter time.Duration

	// LockAfter this many tries.
	LockAfter int
	// LockWindow is the waiting time before the number of attemps are reset.
	LockWindow time.Duration
	// LockDuration is how long an account is locked for.
	LockDuration time.Duration

	// EmailFrom is the email address authboss e-mails come from.
	EmailFrom string
	// EmailSubjectPrefix is used to add something to the front of the authboss
	// email subjects.
	EmailSubjectPrefix string

	// XSRFName is the name of the xsrf token to put in the hidden form fields.
	XSRFName string
	// XSRFMaker is a function that returns an xsrf token for the current non-POST request.
	XSRFMaker XSRF

	// Storer is the interface through which Authboss accesses the web apps database.
	Storer Storer
	// OAuth2Storer is a different kind of storer only meant for OAuth2.
	OAuth2Storer OAuth2Storer
	// CookieStoreMaker must be defined to provide an interface capapable of storing cookies
	// for the given response, and reading them from the request.
	CookieStoreMaker CookieStoreMaker
	// SessionStoreMaker must be defined to provide an interface capable of storing session-only
	// values for the given response, and reading them from the request.
	SessionStoreMaker SessionStoreMaker
	// LogWriter is written to when errors occur, as well as on startup to show which modules are loaded
	// and which routes they registered. By default writes to io.Discard.
	LogWriter io.Writer
	// Callbacks is an internal mechanism that can be used by implementers and will be set automatically.
	Callbacks *Callbacks
	// Mailer is the mailer being used to send e-mails out. Authboss defines two loggers for use
	// LogMailer and SMTPMailer, the default is a LogMailer to io.Discard.
	Mailer Mailer
}

// NewConfig creates a config full of healthy default values.
// Notable exceptions to default values are the Storers.
// This method is called automatically on startup and is set to authboss.Cfg
// so implementers need not call it. Primarily exported for testing.
func NewConfig() *Config {
	return &Config{
		MountPath:  "/",
		ViewsPath:  "./",
		RootURL:    "http://localhost:8080",
		BCryptCost: bcrypt.DefaultCost,

		PrimaryID: StoreEmail,

		Layout:          template.Must(template.New("").Parse(`<!DOCTYPE html><html><body>{{template "authboss" .}}</body></html>`)),
		LayoutHTMLEmail: template.Must(template.New("").Parse(`<!DOCTYPE html><html><body>{{template "authboss" .}}</body></html>`)),
		LayoutTextEmail: template.Must(template.New("").Parse(`{{template "authboss" .}}`)),

		AuthLoginOKPath:   "/",
		AuthLoginFailPath: "/",
		AuthLogoutOKPath:  "/",

		RecoverOKPath:        "/",
		RecoverTokenDuration: time.Duration(24) * time.Hour,

		RegisterOKPath: "/",

		Policies: []Validator{
			Rules{
				FieldName:       "username",
				Required:        true,
				MinLength:       2,
				MaxLength:       4,
				AllowWhitespace: false,
			},
			Rules{
				FieldName: "password",
				Required:  true,
				MinLength: 4,
				MaxLength: 8,

				AllowWhitespace: false,
			},
		},
		ConfirmFields: []string{
			StorePassword, ConfirmPrefix + StorePassword,
		},

		ExpireAfter: 60 * time.Minute,

		LockAfter:    3,
		LockWindow:   5 * time.Minute,
		LockDuration: 5 * time.Hour,

		LogWriter: NewDefaultLogger(),
		Callbacks: NewCallbacks(),
		Mailer:    LogMailer(ioutil.Discard),
	}
}
