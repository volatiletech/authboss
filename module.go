package authboss

var modules = make(map[string]Modularizer)

var ModuleAttrMeta = make(AttributeMeta)

// Modularizer should be implemented by all the authboss modules.
type Modularizer interface {
	Initialize(*Config) error
	Routes() RouteTable
	Storage() StorageOptions
}

// RegisterModule with the core providing all the necessary information to
// integrate into authboss.
func RegisterModule(name string, m Modularizer) {
	modules[name] = m

	for k, v := range m.Storage() {
		ModuleAttrMeta[k] = v
	}
}

// LoadedModules returns a list of modules that are currently loaded.
func LoadedModules() []string {
	mods := make([]string, len(modules))
	i := 0
	for k, _ := range modules {
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
