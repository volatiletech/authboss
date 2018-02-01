package authboss

import (
	"io/ioutil"
	"testing"
)

func TestAuthBossInit(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.LogWriter = ioutil.Discard
	ab.ViewLoader = mockRenderLoader{}
	ab.MailViewLoader = mockRenderLoader{}
	err := ab.Init()
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAuthbossUpdatePassword(t *testing.T) {
	t.Skip("TODO(aarondl): Implement")
	/*
		t.Parallel()

		ab := New()
		session := mockClientStore{}
		cookies := mockClientStore{}
		ab.SessionStoreMaker = newMockClientStoreMaker(session)
		ab.CookieStoreMaker = newMockClientStoreMaker(cookies)

		called := false
		ab.Callbacks.After(EventPasswordReset, func(ctx context.Context) error {
			called = true
			return nil
		})

		user1 := struct {
			Password string
		}{}
		user2 := struct {
			Password sql.NullString
		}{}

		r, _ := http.NewRequest("GET", "http://localhost", nil)

		called = false
		err := ab.UpdatePassword(nil, r, "newpassword", &user1, func() error { return nil })
		if err != nil {
			t.Error(err)
		}

		if len(user1.Password) == 0 {
			t.Error("Password not updated")
		}
		if !called {
			t.Error("Callbacks should have been called.")
		}

		called = false
		err = ab.UpdatePassword(nil, r, "newpassword", &user2, func() error { return nil })
		if err != nil {
			t.Error(err)
		}

		if !user2.Password.Valid || len(user2.Password.String) == 0 {
			t.Error("Password not updated")
		}
		if !called {
			t.Error("Callbacks should have been called.")
		}

		called = false
		oldPassword := user1.Password
		err = ab.UpdatePassword(nil, r, "", &user1, func() error { return nil })
		if err != nil {
			t.Error(err)
		}

		if user1.Password != oldPassword {
			t.Error("Password not updated")
		}
		if called {
			t.Error("Callbacks should not have been called")
		}
	*/
}

func TestAuthbossUpdatePasswordFail(t *testing.T) {
	t.Skip("TODO(aarondl): Implement")
	/*
		t.Parallel()

		ab := New()

		user1 := struct {
			Password string
		}{}

		anErr := errors.New("anError")
		err := ab.UpdatePassword(nil, nil, "update", &user1, func() error { return anErr })
		if err != anErr {
			t.Error("Expected an specific error:", err)
		}
	*/
}
