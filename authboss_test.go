package authboss

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestMain(main *testing.M) {
	RegisterModule("testmodule", testMod)
	Init()
	code := main.Run()
	os.Exit(code)
}

func TestAuthBossInit(t *testing.T) {
	NewConfig()
	err := Init()
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAuthBossRouter(t *testing.T) {
	NewConfig()
	Cfg.Storer = mockStorer{}
	Cfg.CookieStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return mockClientStore{}
	}
	Cfg.SessionStoreMaker = SessionStoreMaker(Cfg.CookieStoreMaker)
	Cfg.MountPath = "/candycanes"

	if err := Init(); err != nil {
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
	NewConfig()
	Cfg.Storer = mockStorer{"joe": Attributes{"email": "john@john.com", "password": "lies"}}
	Cfg.SessionStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return mockClientStore{SessionKey: "joe"}
	}

	if err := Init(); err != nil {
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
