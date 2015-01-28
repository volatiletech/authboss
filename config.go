package authboss

import (
	"io"
	"io/ioutil"
	"net/smtp"
	"time"
)

// Config holds all the configuration for both authboss and it's modules.
type Config struct {
	// MountPath is the path to mount the router at.
	MountPath string
	// ViewsPath is the path to overiding view template files.
	ViewsPath string
	// HostName is self explanitory
	HostName string

	AuthLogoutRoute       string
	AuthLoginSuccessRoute string

	RecoverInitiateRedirect     string
	RecoverInitiateSuccessFlash string

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
		MountPath: "/",
		ViewsPath: "/",

		AuthLogoutRoute:       "/",
		AuthLoginSuccessRoute: "/",

		RecoverInitiateRedirect:     "/login",
		RecoverInitiateSuccessFlash: "An email has been sent with further insructions on how to reset your password",

		LogWriter: ioutil.Discard,
		Callbacks: NewCallbacks(),
		Mailer:    LogMailer(ioutil.Discard),
	}
}
