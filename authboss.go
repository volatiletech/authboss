/*
Package authboss is a modular authentication system for the web. It tries to
remove as much boilerplate and "hard things" as possible so that each time you
start a new web project in Go, you can plug it in, configure and be off to the
races without having to think about how to store passwords or remember tokens.
*/
package authboss // import "gopkg.in/authboss.v1"

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Authboss contains a configuration and other details for running.
type Authboss struct {
	Config
	Callbacks *Callbacks

	loadedModules    map[string]Modularizer
	ModuleAttributes AttributeMeta
	mux              *http.ServeMux
}

// New makes a new instance of authboss with a default
// configuration.
func New() *Authboss {
	ab := &Authboss{
		Callbacks:        NewCallbacks(),
		loadedModules:    make(map[string]Modularizer),
		ModuleAttributes: make(AttributeMeta),
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
		fmt.Fprintf(a.LogWriter, "%-10s Loading\n", "["+name+"]")
		if err := a.loadModule(name); err != nil {
			return fmt.Errorf("[%s] Error Initializing: %v", name, err)
		}
	}

	for _, mod := range a.loadedModules {
		for k, v := range mod.Storage() {
			a.ModuleAttributes[k] = v
		}
	}

	return nil
}

// CurrentUser retrieves the current user from the session and the database.
func (a *Authboss) CurrentUser(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return a.currentUser(a.InitContext(w, r), w, r)
}

func (a *Authboss) currentUser(ctx *Context, w http.ResponseWriter, r *http.Request) (interface{}, error) {
	_, err := a.Callbacks.FireBefore(EventGetUserSession, ctx)
	if err != nil {
		return nil, err
	}

	key, ok := ctx.SessionStorer.Get(SessionKey)
	if !ok {
		return nil, nil
	}

	_, err = a.Callbacks.FireBefore(EventGetUser, ctx)
	if err != nil {
		return nil, err
	}

	var user interface{}

	if index := strings.IndexByte(key, ';'); index > 0 {
		user, err = a.OAuth2Storer.GetOAuth(key[:index], key[index+1:])
	} else {
		user, err = a.Storer.Get(key)
	}

	if err != nil {
		return nil, err
	}

	ctx.User = Unbind(user)

	err = a.Callbacks.FireAfter(EventGetUser, ctx)
	if err != nil {
		return nil, err
	}

	return user, err
}

// CurrentUserP retrieves the current user but panics if it's not available for
// any reason.
func (a *Authboss) CurrentUserP(w http.ResponseWriter, r *http.Request) interface{} {
	i, err := a.CurrentUser(w, r)
	if err != nil {
		panic(err.Error())
	}
	return i
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
	ptPassword string, user interface{}, updater func() error) error {

	updatePwd := len(ptPassword) > 0

	if updatePwd {
		pass, err := bcrypt.GenerateFromPassword([]byte(ptPassword), a.BCryptCost)
		if err != nil {
			return err
		}

		val := reflect.ValueOf(user).Elem()
		field := val.FieldByName("Password")
		if !field.CanSet() {
			return errors.New("authboss: UpdatePassword called without a modifyable user struct")
		}
		fieldPtr := field.Addr()

		if scanner, ok := fieldPtr.Interface().(sql.Scanner); ok {
			if err := scanner.Scan(string(pass)); err != nil {
				return err
			}
		} else {
			field.SetString(string(pass))
		}
	}

	if err := updater(); err != nil {
		return err
	}

	if !updatePwd {
		return nil
	}

	return a.Callbacks.FireAfter(EventPasswordReset, a.InitContext(w, r))
}
