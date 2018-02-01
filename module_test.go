package authboss

import (
	"net/http"
	"testing"
)

const (
	testModName = "testmodule"
)

var (
	testMod = &testModule{}
)

func init() {
	RegisterModule(testModName, testMod)
}

type testModule struct {
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("testhandler", "test")
}

func (t *testModule) Init(a *Authboss) error { return nil }

func TestRegister(t *testing.T) {
	t.Parallel()

	// RegisterModule called by init()
	if _, ok := registeredModules[testModName]; !ok {
		t.Error("Expected module to be saved.")
	}
}

func TestLoadedModules(t *testing.T) {
	t.Parallel()

	// RegisterModule called by init()
	registered := RegisteredModules()
	if len(registered) != 1 {
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
	t.Parallel()

	ab := New()
	if err := ab.Init(); err != nil {
		t.Error(err)
	}

	if loaded := ab.LoadedModules(); len(loaded) == 0 || loaded[0] != testModName {
		t.Error("Loaded modules wrong:", loaded)
	}
}
