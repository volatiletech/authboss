package authboss

import (
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/smtp"
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

	Layout          *template.Template
	LayoutHTMLEmail *template.Template
	LayoutTextEmail *template.Template
	LayoutDataMaker ViewDataMaker

	OAuth2Providers map[string]OAuthProvider

	// ErrorHandler handles would be 500 errors.
	ErrorHandler http.Handler
	// BadRequestHandler handles would be 400 errors.
	BadRequestHandler http.Handler
	// NotFoundHandler handles would be 404 errors.
	NotFoundHandler http.Handler

	AuthLoginOKPath   string
	AuthLoginFailPath string
	AuthLogoutOKPath  string

	RecoverOKPath        string
	RecoverTokenDuration time.Duration

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
	// SMTPAddress is the address of the SMTP server.
	SMTPAddress string
	// SMTPAuth is authentication details for the SMTP server, can be nil and if not
	// will repeat the SMTPAddress, this is intentional.
	SMTPAuth smtp.Auth

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

		RecoverOKPath:        "/",
		RecoverTokenDuration: time.Duration(24) * time.Hour,

		LogWriter: ioutil.Discard,
		Callbacks: NewCallbacks(),
		Mailer:    LogMailer(ioutil.Discard),
	}
}
