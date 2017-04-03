package authboss

import (
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

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

	// Allow the user to be automatically signed in after confirm his account
	AllowInsecureLoginAfterConfirm bool
	// Allow the user to be automatically signed in after reset his password
	AllowLoginAfterResetPassword bool

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
	// PreserveFields are fields used with registration that are to be rendered when
	// post fails.
	PreserveFields []string

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
	// StoreMaker is an alternative to defining Storer directly, which facilitates creating
	// a Storer on demand from the current http request. Unless you have an exceedingly unusual
	// special requirement, defining Storer directly is the preferred pattern; literally the only
	// known use case at the time of this property being added is Google App Engine, which requires
	// the current context as an argument to its datastore API methods. To avoid passing StoreMaker
	// an expired request object, where relevant, calls to this function will never be spun off as
	// goroutines.
	StoreMaker StoreMaker
	// OAuth2Storer is a different kind of storer only meant for OAuth2.
	OAuth2Storer OAuth2Storer
	// OAuth2StoreMaker is an alternative to defining OAuth2Storer directly, which facilitates creating
	// a OAuth2Storer on demand from the current http request. Unless you have an exceedingly unusual
	// special requirement, defining OAuth2Storer directly is the preferred pattern; literally the only
	// known use case at the time of this property being added is Google App Engine, which requires
	// the current context as an argument to its datastore API methods. To avoid passing OAuth2StoreMaker
	// an expired request object, where relevant, calls to this function will never be spun off as
	// goroutines.
	OAuth2StoreMaker OAuth2StoreMaker
	// CookieStoreMaker must be defined to provide an interface capapable of storing cookies
	// for the given response, and reading them from the request.
	CookieStoreMaker CookieStoreMaker
	// SessionStoreMaker must be defined to provide an interface capable of storing session-only
	// values for the given response, and reading them from the request.
	SessionStoreMaker SessionStoreMaker
	// LogWriter is written to when errors occur, as well as on startup to show which modules are loaded
	// and which routes they registered. By default writes to io.Discard.
	LogWriter io.Writer
	// LogWriteMaker is an alternative to defining LogWriter directly, which facilitates creating
	// a LogWriter on demand from the current http request. Unless you have an exceedingly unusual
	// special requirement, defining LogWriter directly is the preferred pattern; literally the only
	// known use case at the time of this property being added is Google App Engine, which requires
	// the current context as an argument to its logging API methods. To avoid passing LogWriteMaker
	// an expired request object, where relevant, calls to this function will never be spun off as
	// goroutines.
	LogWriteMaker LogWriteMaker
	// Mailer is the mailer being used to send e-mails out. Authboss defines two loggers for use
	// LogMailer and SMTPMailer, the default is a LogMailer to io.Discard.
	Mailer Mailer
	// MailMaker is an alternative to defining Mailer directly, which facilitates creating
	// a Mailer on demand from the current http request. Unless you have an exceedingly unusual
	// special requirement, defining Mailer directly is the preferred pattern; literally the only
	// known use case at the time of this property being added is Google App Engine, which requires
	// the current context as an argument to its mail API methods. To avoid passing MailMaker
	// an expired request object, where relevant, calls to this function will never be spun off as
	// goroutines.
	MailMaker MailMaker
	// ContextProvider provides a context for a given request
	ContextProvider func(*http.Request) context.Context
}

// Defaults sets the configuration's default values.
func (c *Config) Defaults() {
	c.MountPath = "/"
	c.ViewsPath = "./"
	c.RootURL = "http://localhost:8080"
	c.BCryptCost = bcrypt.DefaultCost

	c.PrimaryID = StoreEmail

	c.Layout = template.Must(template.New("").Parse(`<!DOCTYPE html><html><body>{{template "authboss" .}}</body></html>`))
	c.LayoutHTMLEmail = template.Must(template.New("").Parse(`<!DOCTYPE html><html><body>{{template "authboss" .}}</body></html>`))
	c.LayoutTextEmail = template.Must(template.New("").Parse(`{{template "authboss" .}}`))

	c.AuthLoginOKPath = "/"
	c.AuthLoginFailPath = "/"
	c.AuthLogoutOKPath = "/"

	c.RecoverOKPath = "/"
	c.RecoverTokenDuration = time.Duration(24) * time.Hour

	c.RegisterOKPath = "/"

	c.Policies = []Validator{
		Rules{
			FieldName:       "email",
			Required:        true,
			AllowWhitespace: false,
		},
		Rules{
			FieldName:       "password",
			Required:        true,
			MinLength:       4,
			MaxLength:       8,
			AllowWhitespace: false,
		},
	}
	c.ConfirmFields = []string{
		StorePassword, ConfirmPrefix + StorePassword,
	}

	c.ExpireAfter = 60 * time.Minute

	c.LockAfter = 3
	c.LockWindow = 5 * time.Minute
	c.LockDuration = 5 * time.Hour

	c.LogWriter = NewDefaultLogger()
	c.Mailer = LogMailer(ioutil.Discard)
	c.ContextProvider = func(req *http.Request) context.Context {
		return context.TODO()
	}
}
