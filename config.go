package authboss

import (
	"io"
	"io/ioutil"
)

// Config holds all the configuration for both authboss and it's modules.
type Config struct {
	MountPath string `json:"mountPath" xml:"mountPath"`
	ViewsPath string `json:"viewsPath" xml:"viewsPath"`

	AuthLogoutRoute string `json:"authLogoutRoute" xml:"authLogoutRoute"`

	Storer    Storer    `json:"-" xml:"-"`
	LogWriter io.Writer `json:"-" xml:"-"`
}

// NewConfig creates a new config full of default values ready to override.
func NewConfig() *Config {
	return &Config{
		MountPath: "/",
		ViewsPath: "/",
		LogWriter: ioutil.Discard,
	}
}
