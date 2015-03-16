package authboss

var modules = make(map[string]Modularizer)

// ModuleAttributes is the list of attributes required by all the loaded modules.
// Authboss implementers can use this at runtime to determine what data is necessary
// to store.
var ModuleAttributes = make(AttributeMeta)

// Modularizer should be implemented by all the authboss modules.
type Modularizer interface {
	Initialize() error
	Routes() RouteTable
	Storage() StorageOptions
}

// RegisterModule with the core providing all the necessary information to
// integrate into authboss.
func RegisterModule(name string, m Modularizer) {
	modules[name] = m

	for k, v := range m.Storage() {
		ModuleAttributes[k] = v
	}
}

// LoadedModules returns a list of modules that are currently loaded.
func LoadedModules() []string {
	mods := make([]string, len(modules))
	i := 0
	for k := range modules {
		mods[i] = k
		i++
	}

	return mods
}

// IsLoaded checks if a specific module is loaded.
func IsLoaded(mod string) bool {
	_, ok := modules[mod]
	return ok
}
