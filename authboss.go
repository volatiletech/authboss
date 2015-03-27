/*
Package authboss is a modular authentication system for the web. It tries to
remove as much boilerplate and "hard things" as possible so that each time you
start a new web project in Go, you can plug it in, configure and be off to the
races without having to think about how to store passwords or remember tokens.
*/
package authboss // import "gopkg.in/authboss.v0"

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Init authboss and it's loaded modules.
func Init() error {
	for name, mod := range modules {
		fmt.Fprintf(Cfg.LogWriter, "%-10s Initializing\n", "["+name+"]")
		if err := mod.Initialize(); err != nil {
			return fmt.Errorf("[%s] Error Initializing: %v", name, err)
		}
	}

	return nil
}

// CurrentUser retrieves the current user from the session and the database.
func CurrentUser(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx, err := ContextFromRequest(r)
	if err != nil {
		return nil, err
	}

	ctx.SessionStorer = clientStoreWrapper{Cfg.SessionStoreMaker(w, r)}
	ctx.CookieStorer = clientStoreWrapper{Cfg.CookieStoreMaker(w, r)}

	_, err = Cfg.Callbacks.FireBefore(EventGetUserSession, ctx)
	if err != nil {
		return nil, err
	}

	key, ok := ctx.SessionStorer.Get(SessionKey)
	if !ok {
		return nil, nil
	}

	err = ctx.LoadUser(key)
	if err != nil {
		return nil, err
	}

	_, err = Cfg.Callbacks.FireBefore(EventGet, ctx)
	if err != nil {
		return nil, err
	}

	if index := strings.IndexByte(key, ';'); index > 0 {
		return Cfg.OAuth2Storer.GetOAuth(key[:index], key[index+1:])
	}

	return Cfg.Storer.Get(key)
}

// CurrentUserP retrieves the current user but panics if it's not available for
// any reason.
func CurrentUserP(w http.ResponseWriter, r *http.Request) interface{} {
	i, err := CurrentUser(w, r)
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
func UpdatePassword(w http.ResponseWriter, r *http.Request,
	ptPassword string, user interface{}, updater func() error) error {

	updatePwd := len(ptPassword) > 0

	if updatePwd {
		pass, err := bcrypt.GenerateFromPassword([]byte(ptPassword), Cfg.BCryptCost)
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

	ctx, err := ContextFromRequest(r)
	if err != nil {
		return err
	}
	ctx.SessionStorer = clientStoreWrapper{Cfg.SessionStoreMaker(w, r)}
	ctx.CookieStorer = clientStoreWrapper{Cfg.CookieStoreMaker(w, r)}
	return Cfg.Callbacks.FireAfter(EventPasswordReset, ctx)
}
