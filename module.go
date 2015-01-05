package authboss

import (
	"net/http"
)

var modules = make(map[string]Modularizer)

// RouteTable is a routing table from a path to a handlerfunc.
type RouteTable map[string]http.HandlerFunc

// StorageOptions is a map depicting the things a module must be able to store.
type StorageOptions map[string]DataType

type Modularizer interface {
	Initialize(*Config) error
	Routes() RouteTable
	Storage() StorageOptions
}

// RegisterModule with the core providing all the necessary information to
// integrate into authboss.
func RegisterModule(name string, m Modularizer) {
	modules[name] = m
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
