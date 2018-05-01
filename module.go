package authboss

import (
	"context"
	"net/http"
	"reflect"
)

var registeredModules = make(map[string]Moduler)

// Moduler should be implemented by all the authboss modules.
type Moduler interface {
	// Init the module
	Init(*Authboss) error
}

// RegisterModule with the core providing all the necessary information to
// integrate into authboss.
func RegisterModule(name string, m Moduler) {
	registeredModules[name] = m
}

// RegisteredModules returns a list of modules that are currently registered.
func RegisteredModules() []string {
	mods := make([]string, len(registeredModules))
	i := 0
	for k := range registeredModules {
		mods[i] = k
		i++
	}

	return mods
}

// LoadedModules returns a list of modules that are currently loaded.
func (a *Authboss) LoadedModules() []string {
	mods := make([]string, len(a.loadedModules))
	i := 0
	for k := range a.loadedModules {
		mods[i] = k
		i++
	}

	return mods
}

// IsLoaded checks if a specific module is loaded.
func (a *Authboss) IsLoaded(mod string) bool {
	_, ok := a.loadedModules[mod]
	return ok
}

// loadModule loads a particular module. It uses reflection to create a new
// instance of the module type. The original value is copied, but not deep copied
// so care should be taken to make sure most initialization happens inside the Initialize()
// method of the module.
//
// This method exists so many copies of authboss can be loaded and initialized at the same time
// if we didn't use this, then the registeredModules instances of the modules would end up used
// by the first instance of authboss.
func (a *Authboss) loadModule(name string) error {
	module, ok := registeredModules[name]
	if !ok {
		panic("could not find module: " + name)
	}

	var wasPtr bool
	modVal := reflect.ValueOf(module)
	if modVal.Kind() == reflect.Ptr {
		wasPtr = true
		modVal = modVal.Elem()
	}

	modType := modVal.Type()
	value := reflect.New(modType)
	if !wasPtr {
		value = value.Elem()
		value.Set(modVal)
	} else {
		value.Elem().Set(modVal)
	}

	mod, ok := value.Interface().(Moduler)
	a.loadedModules[name] = mod
	return mod.Init(a)
}

// ModuleListMiddleware puts a map in the data that can be used
// to provide the renderer with information about which pieces of the
// views to show.
// Data looks like:
// map[modulename] = Moduler
//
// The Moduler interface type should be ignored, and the key being present
// or not is the only important point. Copying this data structure ignores
// allocations.
func ModuleListMiddleware(ab *Authboss) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var data HTMLData

			ctx := r.Context()
			dataIntf := ctx.Value(CTXKeyData)
			if dataIntf != nil {
				data = dataIntf.(HTMLData)
			} else {
				data = HTMLData{}
			}

			data[DataModules] = ab.loadedModules
			r = r.WithContext(context.WithValue(ctx, CTXKeyData, data))
			next.ServeHTTP(w, r)
		})
	}
}
