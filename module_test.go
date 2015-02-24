package authboss

import (
	"net/http"
	"testing"
)

const testModName = "testmodule"

type testModule struct {
	s StorageOptions
	r RouteTable
}

var testMod = &testModule{
	r: RouteTable{
		"/testroute": testHandler,
	},
}

func testHandler(ctx *Context, w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("testhandler", "test")
	return nil
}

func (t *testModule) Initialize() error       { return nil }
func (t *testModule) Routes() RouteTable      { return t.r }
func (t *testModule) Storage() StorageOptions { return t.s }

func TestRegister(t *testing.T) {
	// RegisterModule called by TestMain.

	if _, ok := modules["testmodule"]; !ok {
		t.Error("Expected module to be saved.")
	}

	if !IsLoaded("testmodule") {
		t.Error("Expected module to be loaded.")
	}
}

func TestLoadedModules(t *testing.T) {
	// RegisterModule called by TestMain.

	loadedMods := LoadedModules()
	if len(loadedMods) != 1 {
		t.Error("Expected only a single module to be loaded.")
	} else if loadedMods[0] != "testmodule" {
		t.Error("Expected testmodule to be loaded.")
	}
}
