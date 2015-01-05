/*
Package authboss is a modular authentication system for the web. It tries to
remove as much boilerplate and "hard things" as possible so that each time you
start a new web project in Go, you can plug it in, configure and be off to the
races without having to think about the hard questions like how to store
Remember Me tokens, or passwords.
*/
package authboss // import "gopkg.in/authboss.v0"

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
)

var logger io.Writer = ioutil.Discard

// Init authboss and it's loaded modules with a configuration.
func Init(config *Config) error {
	if config.Storer == nil {
		return errors.New("Configuration must provide a storer.")
	}

	logger = config.LogWriter

	for name, mod := range modules {
		fmt.Fprintf(logger, "[%-10s] Initializing\n", name)
		if err := mod.Initialize(config); err != nil {
			return fmt.Errorf("[%s] Error Initializing: %v", name, err)
		}
	}

	return nil
}

// Router returns a router to be mounted at some mountpoint.
func Router(config *Config) http.Handler {
	mux := http.NewServeMux()

	for name, mod := range modules {
		for route, handler := range mod.Routes() {
			fmt.Fprintf(logger, "[%-10s] Register Route: %s\n", name)
			mux.HandleFunc(path.Join(config.MountPath, route), handler)
		}
	}

	return http.StripPrefix(config.MountPath, mux)
}
