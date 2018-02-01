package authboss

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
