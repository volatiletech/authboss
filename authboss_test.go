package authboss

import (
	"context"
	"testing"
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
