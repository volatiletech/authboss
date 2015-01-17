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

	c.Storer = mockStorer{}
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
	c.Storer = mockStorer{}
	c.CookieStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return mockClientStore{}
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

func TestAuthBossCurrentUser(t *testing.T) {
	c := NewConfig()
	c.Storer = mockStorer{"joe": Attributes{"email": "john@john.com", "password": "lies"}}
	c.SessionStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return mockClientStore{SessionKey: "joe"}
	}

	if err := Init(c); err != nil {
		t.Error("Unexpected error:", err)
	}

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "localhost", nil)

	userStruct := CurrentUserP(rec, req)
	us := userStruct.(*mockUser)

	if us.Email != "john@john.com" || us.Password != "lies" {
		t.Error("Wrong user found!")
	}
}
