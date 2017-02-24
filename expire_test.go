package authboss

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// These tests use the global variable nowTime so cannot be parallelized

func TestDudeIsExpired(t *testing.T) {
	ab := New()
	session := mockClientStore{SessionKey: "username"}
	ab.refreshExpiry(session)

	// No t.Parallel()
	nowTime = func() time.Time {
		return time.Now().UTC().Add(ab.ExpireAfter * 2)
	}
	defer func() {
		nowTime = time.Now
	}()

	ab.SessionStoreMaker = newMockClientStoreMaker(session)

	r, _ := http.NewRequest("GET", "tra/la/la", nil)
	w := httptest.NewRecorder()
	called := false

	m := ab.ExpireMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	m.ServeHTTP(w, r)

	if !called {
		t.Error("Expected middleware to call handler")
	}

	if key, ok := session.Get(SessionKey); ok {
		t.Error("Unexpected session key:", key)
	}

	if key, ok := session.Get(SessionLastAction); ok {
		t.Error("Unexpected last action key:", key)
	}
}

func TestDudeIsNotExpired(t *testing.T) {
	ab := New()
	session := mockClientStore{SessionKey: "username"}
	ab.refreshExpiry(session)

	// No t.Parallel()
	nowTime = func() time.Time {
		return time.Now().UTC().Add(ab.ExpireAfter / 2)
	}
	defer func() {
		nowTime = time.Now
	}()

	ab.SessionStoreMaker = newMockClientStoreMaker(session)

	r, _ := http.NewRequest("GET", "tra/la/la", nil)
	w := httptest.NewRecorder()
	called := false

	m := ab.ExpireMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	m.ServeHTTP(w, r)

	if !called {
		t.Error("Expected middleware to call handler")
	}

	if key, ok := session.Get(SessionKey); !ok {
		t.Error("Expected session key:", key)
	}
}
