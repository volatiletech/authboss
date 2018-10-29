package authboss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestAuthBossInit(t *testing.T) {
	t.Parallel()

	ab := New()
	err := ab.Init()
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAuthbossUpdatePassword(t *testing.T) {
	t.Parallel()

	user := &mockUser{}
	storer := newMockServerStorer()

	ab := New()
	ab.Config.Storage.Server = storer

	if err := ab.UpdatePassword(context.Background(), user, "hello world"); err != nil {
		t.Error(err)
	}

	if len(user.Password) == 0 {
		t.Error("password was not updated")
	}
}

type testRedirector struct {
	Opts RedirectOptions
}

func (r *testRedirector) Redirect(w http.ResponseWriter, req *http.Request, ro RedirectOptions) error {
	r.Opts = ro
	if len(ro.RedirectPath) == 0 {
		panic("no redirect path on redirect call")
	}
	http.Redirect(w, req, ro.RedirectPath, ro.Code)
	return nil
}

func TestAuthbossMiddleware(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Core.Logger = mockLogger{}
	ab.Storage.Server = &mockServerStorer{
		Users: map[string]*mockUser{
			"test@test.com": &mockUser{},
		},
	}

	setupMore := func(mountPathed, redirect, allowHalfAuth, force2fa bool) (*httptest.ResponseRecorder, bool, bool) {
		r := httptest.NewRequest("GET", "/super/secret", nil)
		rec := httptest.NewRecorder()
		w := ab.NewResponse(rec)

		var err error
		r, err = ab.LoadClientState(w, r)
		if err != nil {
			t.Fatal(err)
		}

		var mid func(http.Handler) http.Handler
		if !mountPathed {
			mid = Middleware(ab, redirect, allowHalfAuth, force2fa)
		} else {
			mid = MountedMiddleware(ab, true, redirect, allowHalfAuth, force2fa)
		}
		var called, hadUser bool
		server := mid(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			hadUser = r.Context().Value(CTXKeyUser) != nil
			w.WriteHeader(http.StatusOK)
		}))

		server.ServeHTTP(w, r)

		return rec, called, hadUser
	}

	t.Run("Accept", func(t *testing.T) {
		ab.Storage.SessionState = mockClientStateReadWriter{
			state: mockClientState{SessionKey: "test@test.com"},
		}

		_, called, hadUser := setupMore(false, false, false, false)

		if !called {
			t.Error("should have been called")
		}
		if !hadUser {
			t.Error("should have had user")
		}
	})
	t.Run("AcceptHalfAuth", func(t *testing.T) {
		ab.Storage.SessionState = mockClientStateReadWriter{
			state: mockClientState{SessionKey: "test@test.com", SessionHalfAuthKey: "true"},
		}

		_, called, hadUser := setupMore(false, false, false, false)

		if !called {
			t.Error("should have been called")
		}
		if !hadUser {
			t.Error("should have had user")
		}
	})
	t.Run("Accept2FA", func(t *testing.T) {
		ab.Storage.SessionState = mockClientStateReadWriter{
			state: mockClientState{SessionKey: "test@test.com", Session2FA: "sms"},
		}

		_, called, hadUser := setupMore(false, false, false, true)

		if !called {
			t.Error("should have been called")
		}
		if !hadUser {
			t.Error("should have had user")
		}
	})
	t.Run("Reject404", func(t *testing.T) {
		ab.Storage.SessionState = mockClientStateReadWriter{}

		rec, called, hadUser := setupMore(false, false, false, false)

		spew.Dump(ab.Storage)

		if rec.Code != http.StatusNotFound {
			t.Error("wrong code:", rec.Code)
		}
		if called {
			t.Error("should not have been called")
		}
		if hadUser {
			t.Error("should not have had user")
		}
	})
	t.Run("RejectRedirect", func(t *testing.T) {
		redir := &testRedirector{}
		ab.Config.Core.Redirector = redir

		ab.Storage.SessionState = mockClientStateReadWriter{}

		_, called, hadUser := setupMore(false, true, false, false)

		if redir.Opts.Code != http.StatusTemporaryRedirect {
			t.Error("code was wrong:", redir.Opts.Code)
		}
		if redir.Opts.RedirectPath != "/auth/login?redir=%2Fsuper%2Fsecret" {
			t.Error("redirect path was wrong:", redir.Opts.RedirectPath)
		}
		if called {
			t.Error("should not have been called")
		}
		if hadUser {
			t.Error("should not have had user")
		}
	})
	t.Run("RejectMountpathedRedirect", func(t *testing.T) {
		redir := &testRedirector{}
		ab.Config.Core.Redirector = redir

		ab.Storage.SessionState = mockClientStateReadWriter{}

		_, called, hadUser := setupMore(true, true, false, false)

		if redir.Opts.Code != http.StatusTemporaryRedirect {
			t.Error("code was wrong:", redir.Opts.Code)
		}
		if redir.Opts.RedirectPath != "/auth/login?redir=%2Fauth%2Fsuper%2Fsecret" {
			t.Error("redirect path was wrong:", redir.Opts.RedirectPath)
		}
		if called {
			t.Error("should not have been called")
		}
		if hadUser {
			t.Error("should not have had user")
		}
	})
	t.Run("RejectHalfAuth", func(t *testing.T) {
		ab.Storage.SessionState = mockClientStateReadWriter{
			state: mockClientState{SessionKey: "test@test.com", SessionHalfAuthKey: "true"},
		}

		rec, called, hadUser := setupMore(false, false, true, false)

		if rec.Code != http.StatusNotFound {
			t.Error("wrong code:", rec.Code)
		}
		if called {
			t.Error("should not have been called")
		}
		if hadUser {
			t.Error("should not have had user")
		}
	})
	t.Run("RejectNo2FA", func(t *testing.T) {
		ab.Storage.SessionState = mockClientStateReadWriter{
			state: mockClientState{SessionKey: "test@test.com"},
		}

		rec, called, hadUser := setupMore(false, false, true, true)

		if rec.Code != http.StatusNotFound {
			t.Error("wrong code:", rec.Code)
		}
		if called {
			t.Error("should not have been called")
		}
		if hadUser {
			t.Error("should not have had user")
		}
	})
}
