package authboss

import (
	"io/ioutil"
	"net/http"
	"testing"
)

const testModName = "testmodule"

func init() {
	RegisterModule(testModName, testMod)
}

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

func (t *testModule) Initialize(a *Authboss) error { return nil }
func (t *testModule) Routes() RouteTable           { return t.r }
func (t *testModule) Storage() StorageOptions      { return t.s }

func TestRegister(t *testing.T) {
	// RegisterModule called by init()
	if _, ok := registeredModules[testModName]; !ok {
		t.Error("Expected module to be saved.")
	}
}

func TestLoadedModules(t *testing.T) {
	// RegisterModule called by init()
	registered := RegisteredModules()
	if len(registered) != 2 { // There is another test module loaded from router
		t.Error("Expected only a single module to be loaded.")
	} else {
		found := false
		for _, name := range registered {
			if name == testModName {
				found = true
				break
			}
		}
		if !found {
			t.Error("It should have found the module:", registered)
		}
	}
}

func TestIsLoaded(t *testing.T) {
	ab := New()
	ab.LogWriter = ioutil.Discard
	if err := ab.Init(testModName); err != nil {
		t.Error(err)
	}

	if loaded := ab.LoadedModules(); len(loaded) == 0 || loaded[0] != testModName {
		t.Error("Loaded modules wrong:", loaded)
	}
}
