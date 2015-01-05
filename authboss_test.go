package authboss

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestMain(main *testing.M) {
	RegisterModule("testmodule", testMod)
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
	t.Parallel()

	c := NewConfig()
	c.MountPath = "/candycanes"
	c.LogWriter = os.Stdout

	router := Router(c)

	r, _ := http.NewRequest("GET", "/candycanes/testroute", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, r)

	if response.Header().Get("testmodule") != "test" {
		t.Error("Expected a header to have been set.")
	}
}
