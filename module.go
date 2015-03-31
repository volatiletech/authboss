package authboss

import "reflect"

var registeredModules = make(map[string]Modularizer)

// Modularizer should be implemented by all the authboss modules.
type Modularizer interface {
	Initialize(*Authboss) error
	Routes() RouteTable
	Storage() StorageOptions
}

// RegisterModule with the core providing all the necessary information to
// integrate into authboss.
func RegisterModule(name string, m Modularizer) {
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

// loadModule loads a particular module. It uses reflection to create a new
// instance of the module type. The original value is copied, but not deep copied
// so care should be taken to make sure most initialization happens inside the Initialize()
// method of the module.
func (a *Authboss) loadModule(name string) error {
	module, ok := registeredModules[name]
	if !ok {
		panic("Could not find module: " + name)
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
	mod, ok := value.Interface().(Modularizer)
	a.loadedModules[name] = mod
	return mod.Initialize(a)
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
