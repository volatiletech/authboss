package authboss

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type clientStoreMock struct{}

func (c clientStoreMock) Get(_ string) (string, bool) { return "", false }
func (c clientStoreMock) Put(_, _ string)             {}
func (c clientStoreMock) Del(_ string)                {}

func TestMain(main *testing.M) {
	RegisterModule("testmodule", testMod)
	Init(NewConfig())
	code := main.Run()
	os.Exit(code)
}

func TestAuthBossInit(t *testing.T) {
	c := NewConfig()

	err := Init(c)
	if err == nil || !strings.Contains(err.Error(), "storer") {
		t.Error("Expected error about a storer, got:", err)
	}

	c.Storer = testStorer(0)
	err = Init(c)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if testMod.c == nil {
		t.Error("Expected the modules to be passed the config.")
	}
}

func TestAuthBossRouter(t *testing.T) {
	c := NewConfig()
	c.Storer = testStorer(0)
	c.CookieStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return clientStoreMock{}
	}
	c.SessionStoreMaker = SessionStoreMaker(c.CookieStoreMaker)
	c.MountPath = "/candycanes"

	if err := Init(c); err != nil {
		t.Error("Unexpected error:", err)
	}
	router := NewRouter()

	r, _ := http.NewRequest("GET", "/candycanes/testroute", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, r)

	if response.Header().Get("testhandler") != "test" {
		t.Error("Expected a header to have been set.")
	}
}
