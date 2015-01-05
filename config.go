package authboss

import (
	"io"
	"io/ioutil"
)

// Config holds all the configuration for both authboss and it's modules.
type Config struct {
	MountPath string `json:"mountPath" xml:"mountPath"`

	AuthLoginPageURI   string `json:"authLoginPage" xml:"authLoginPage"`
	AuthLogoutRedirect string `json:"authLogoutRedirect" xml:"authLogoutRedirect"`

	Storer    Storer    `json:"-" xml:"-"`
	LogWriter io.Writer `json:"-" xml:"-"`
}

// NewConfig creates a new config full of default values ready to override.
func NewConfig() *Config {
	return &Config{
		LogWriter: ioutil.Discard,
	}
}
