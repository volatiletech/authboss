package authboss

import (
	"net/http"
	"net/http/httptest"
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

func TestModuleLoadedMiddleware(t *testing.T) {
	t.Parallel()

	ab := New()

	ab.loadedModules = map[string]Moduler{
		"recover": nil,
		"auth":    nil,
		"oauth2":  nil,
	}
	ab.Config.Modules.OAuth2Providers = map[string]OAuth2Provider{
		"google": OAuth2Provider{},
	}

	var mods map[string]bool
	server := ModuleListMiddleware(ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := r.Context().Value(CTXKeyData).(HTMLData)
		mods = data[DataModules].(map[string]bool)
	}))

	server.ServeHTTP(nil, httptest.NewRequest("GET", "/", nil))

	if len(mods) != 4 {
		t.Error("want 4 modules, got:", len(mods))
	}

	if _, ok := mods["auth"]; !ok {
		t.Error("auth should be loaded")
	}
	if _, ok := mods["recover"]; !ok {
		t.Error("recover should be loaded")
	}
	if _, ok := mods["oauth2"]; !ok {
		t.Error("modules should include oauth2.google")
	}
	if _, ok := mods["oauth2.google"]; !ok {
		t.Error("modules should include oauth2.google")
	}
}
