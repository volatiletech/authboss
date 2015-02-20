/*
Package authboss is a modular authentication system for the web. It tries to
remove as much boilerplate and "hard things" as possible so that each time you
start a new web project in Go, you can plug it in, configure and be off to the
races without having to think about the hard questions like how to store
Remember Me tokens, or passwords.
*/
package authboss // import "gopkg.in/authboss.v0"

import (
	"fmt"
	"net/http"
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
	sessions := Cfg.SessionStoreMaker(w, r)
	key, ok := sessions.Get(SessionKey)
	if !ok {
		return nil, nil
	}

	ctx, err := ContextFromRequest(r)
	if err != nil {
		return nil, err
	}

	err = ctx.LoadUser(key)
	if err != nil {
		return nil, err
	}

	_, err = Cfg.Callbacks.FireBefore(EventGet, ctx)
	if err != nil {
		return nil, err
	}

	return Cfg.Storer.Get(key, ModuleAttrMeta)
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
