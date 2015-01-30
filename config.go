package authboss

import (
	"io"
	"io/ioutil"
	"net/smtp"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config holds all the configuration for both authboss and it's modules.
type Config struct {
	// MountPath is the path to mount the router at.
	MountPath string
	// ViewsPath is the path to overiding view template files.
	ViewsPath string
	// HostName is self explanitory
	HostName string
	// BCryptPasswordCost is self explanitory.
	BCryptCost int

	AuthLogoutRoute       string
	AuthLoginSuccessRoute string

	RecoverRedirect             string
	RecoverInitiateSuccessFlash string
	RecoverTokenDuration        time.Duration
	RecoverTokenExpiredFlash    string
	RecoverFailedErrorFlash     string

	Policies      []Validator
	ConfirmFields []string

	ExpireAfter  time.Duration
	LockAfter    int
	LockWindow   time.Duration
	LockDuration time.Duration

	EmailFrom          string
	EmailSubjectPrefix string
	SMTPAddress        string
	SMTPAuth           smtp.Auth

	XSRFName  string
	XSRFMaker XSRF

	Storer            Storer
	CookieStoreMaker  CookieStoreMaker
	SessionStoreMaker SessionStoreMaker
	LogWriter         io.Writer
	Callbacks         *Callbacks
	Mailer            Mailer
}

// NewConfig creates a new config full of default values ready to override.
func NewConfig() *Config {
	return &Config{
		MountPath:  "/",
		ViewsPath:  "/",
		HostName:   "localhost:8080",
		BCryptCost: bcrypt.DefaultCost,

		AuthLogoutRoute:       "/",
		AuthLoginSuccessRoute: "/",

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
		ConfirmFields: []string{"username", "confirmUsername", "password", "confirmPassword"},

		RecoverRedirect:             "/login",
		RecoverInitiateSuccessFlash: "An email has been sent with further insructions on how to reset your password",
		RecoverTokenDuration:        time.Duration(24) * time.Hour,
		RecoverTokenExpiredFlash:    "Account recovery request has expired.  Please try agian.",
		RecoverFailedErrorFlash:     "Account recovery has failed.  Please contact tech support.",

		LogWriter: ioutil.Discard,
		Callbacks: NewCallbacks(),
		Mailer:    LogMailer(ioutil.Discard),
	}
}
