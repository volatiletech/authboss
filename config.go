package authboss

import (
	"io"
	"io/ioutil"
)

// Config holds all the configuration for both authboss and it's modules.
type Config struct {
	MountPath string `json:"mountPath" xml:"mountPath"`
	ViewsPath string `json:"viewsPath" xml:"viewsPath"`

	AuthLogoutRoute       string `json:"authLogoutRoute" xml:"authLogoutRoute"`
	AuthLoginSuccessRoute string `json:"authLoginSuccessRoute" xml:"authLoginSuccessRoute"`

	RecoverFromEmail string `json:"recoverFromEmail" xml:"recoverFromEmail"`

	ValidateEmail    Validator `json:"-" xml:"-"`
	ValidateUsername Validator `json:"-" xml:"-"`
	ValidatePassword Validator `json:"-" xml:"-"`

	Storer            Storer            `json:"-" xml:"-"`
	CookieStoreMaker  CookieStoreMaker  `json:"-" xml:"-"`
	SessionStoreMaker SessionStoreMaker `json:"-" xml:"-"`
	LogWriter         io.Writer         `json:"-" xml:"-"`
	Callbacks         *Callbacks        `json:"-" xml:"-"`
	Mailer            Mailer            `json:"-" xml:"-"`
}

// NewConfig creates a new config full of default values ready to override.
func NewConfig() *Config {
	return &Config{
		MountPath: "/",
		ViewsPath: "/",

		AuthLogoutRoute:       "/",
		AuthLoginSuccessRoute: "/",

		RecoverFromEmail: "no-reply@authboss.com",

		LogWriter: ioutil.Discard,
		Callbacks: NewCallbacks(),
		Mailer:    MailerLog,
	}
}
