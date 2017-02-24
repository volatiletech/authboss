/*
Package authboss is a modular authentication system for the web. It tries to
remove as much boilerplate and "hard things" as possible so that each time you
start a new web project in Go, you can plug it in, configure and be off to the
races without having to think about how to store passwords or remember tokens.
*/
package authboss

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// Authboss contains a configuration and other details for running.
type Authboss struct {
	Config
	Callbacks *Callbacks

	loadedModules map[string]Modularizer
	mux           *http.ServeMux

	templateNames []string
	renderer      Renderer
}

// New makes a new instance of authboss with a default
// configuration.
func New() *Authboss {
	ab := &Authboss{
		Callbacks:     NewCallbacks(),
		loadedModules: make(map[string]Modularizer),
	}
	ab.Config.Defaults()
	return ab
}

// Init authboss and the requested modules. modulesToLoad is left empty
// all registered modules will be loaded.
func (a *Authboss) Init(modulesToLoad ...string) error {
	if len(modulesToLoad) == 0 {
		modulesToLoad = RegisteredModules()
	}

	for _, name := range modulesToLoad {
		fmt.Fprintf(a.LogWriter, "%-10s loading\n", "["+name+"]")
		if err := a.loadModule(name); err != nil {
			return errors.Wrapf(err, "[%s] error initializing", name)
		}
	}

	renderer, err := a.ViewLoader.Init(a.templateNames)
	if err != nil {
		return errors.Wrap(err, "failed to init view loader")
	}
	a.renderer = renderer

	return nil
}

/*
UpdatePassword should be called to recalculate hashes and do any cleanup
that should occur on password resets. Updater should return an error if the
update to the user failed (for reasons say like validation, duplicate
primary key, etc...). In that case the cleanup will not be performed.

The w and r parameters are for establishing session and cookie storers.

The ptPassword parameter is the new password to update to. updater is called
regardless if this is empty or not, but if it is empty, it will not set a new
password before calling updater.

The user parameter is the user struct which will have it's
Password string/sql.NullString value set to the new bcrypted password. Therefore
it must be passed in as a pointer with the Password field exported or an error
will be returned.

The error returned is returned either from the updater if that produced an error
or from the cleanup routines.
*/
func (a *Authboss) UpdatePassword(w http.ResponseWriter, r *http.Request,
	ptPassword string, user Storer, updater func() error) error {

	/*updatePwd := len(ptPassword) > 0

	if updatePwd {
		pass, err := bcrypt.GenerateFromPassword([]byte(ptPassword), a.BCryptCost)
		if err != nil {
			return err
		}

		user.PutPassword(r.Context(),
	}

	if err := updater(); err != nil {
		return err
	}

	if !updatePwd {
		return nil
	}

	return a.Callbacks.FireAfter(EventPasswordReset, r.Context())*/
	// TODO(aarondl): Fix
	return errors.New("not implemented")
}
