package authboss

import (
	"net/http"
	"testing"
)

const testModName = "testmodule"

type testModule struct {
	c *Config
	s StorageOptions
	r RouteTable
}

var testMod = &testModule{
	r: RouteTable{
		"/testroute": testHandler,
	},
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("testhandler", "test")
}

func (t *testModule) Initialize(c *Config) error {
	t.c = c
	return nil
}

func (t *testModule) Routes() RouteTable {
	return t.r
}

func (t *testModule) Storage() StorageOptions {
	return t.s
}

func TestRegister(t *testing.T) {
	t.Parallel()

	// RegisterModule called by TestMain.

	if _, ok := modules["testmodule"]; !ok {
		t.Error("Expected module to be saved.")
	}
}

func TestLoadedModules(t *testing.T) {
	t.Parallel()

	// RegisterModule called by TestMain.

	loadedMods := LoadedModules()
	if len(loadedMods) != 1 {
		t.Error("Expected only a single module to be loaded.")
	} else if loadedMods[0] != "testmodule" {
		t.Error("Expected testmodule to be loaded.")
	}
}
