/*
Package core is essentially just a namespacing for the module system. This
allows the main package for user consumption to remain free of cruft.
*/
package core // import "gopkg.in/authboss.v0/core

// dataType represents the various types that clients must be able to store.
// This type is duplicated from storer.go that we might avoid having users
// importing the core package.
type dataType int

const (
	Integer dataType = iota
	String
	DateTime
)

var modules = make(map[string]module)

type module struct {
	Name           string
	Storage        StorageOptions
	RequiredConfig []string
}

// StorageOptions is a map depicting the things a module must be able to store.
type StorageOptions map[string]DataType

// Register a module with the core providing all the necessary information to
// integrate into authboss.
func Register(name string, storage StorageOptions, requiredConfig ...string) {
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
