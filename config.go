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
	MountPath string `json:"mount_path" xml:"mountPath"`
	// ViewsPath is the path to overiding view template files.
	ViewsPath string `json:"views_path" xml:"viewsPath"`

	AuthLogoutRoute       string `json:"auth_logout_route" xml:"authLogoutRoute"`
	AuthLoginSuccessRoute string `json:"auth_login_success_route" xml:"authLoginSuccessRoute"`

	ValidateEmail    Validator `json:"-" xml:"-"`
	ValidateUsername Validator `json:"-" xml:"-"`
	ValidatePassword Validator `json:"-" xml:"-"`

	ExpireAfter time.Duration `json:"expire_after" xml:"expireAfter"`

	LockAfter    int           `json:"lock_after" xml:"lockAfter"`
	LockWindow   time.Duration `json:"lock_window" xml:"lockWindow"`
	LockDuration time.Duration `json:"lock_duration" xml:"lockDuration"`

	EmailFrom          string `json:"email_from" xml:"emailFrom"`
	EmailSubjectPrefix string `json:"email_subject_prefix" xml:"emailSubjectPrefix"`

	SMTPAddress string    `json:"smtp_address" xml:"smtpAddress"`
	SMTPAuth    smtp.Auth `json:"-" xml:"-"`

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

		LogWriter: ioutil.Discard,
		Callbacks: NewCallbacks(),
		Mailer:    LogMailer(ioutil.Discard),
	}
}
