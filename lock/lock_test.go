package lock

import (
	"testing"
	"time"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

func TestStorage(t *testing.T) {
	authboss.NewConfig()
	storage := L.Storage()
	if _, ok := storage[StoreAttemptNumber]; !ok {
		t.Error("Expected attempt number storage option.")
	}
	if _, ok := storage[StoreAttemptTime]; !ok {
		t.Error("Expected attempt number time option.")
	}
}

func TestBeforeAuth(t *testing.T) {
	authboss.NewConfig()
	ctx := authboss.NewContext()

	if interrupt, err := L.BeforeAuth(ctx); err != errUserMissing {
		t.Error("Expected an error because of missing user:", err)
	} else if interrupt != authboss.InterruptNone {
		t.Error("Interrupt should not be set:", interrupt)
	}

	ctx.User = authboss.Attributes{"locked": true}

	if interrupt, err := L.BeforeAuth(ctx); err != nil {
		t.Error(err)
	} else if interrupt != authboss.InterruptAccountLocked {
		t.Error("Expected a locked interrupt:", interrupt)
	}
}

func TestAfterAuth(t *testing.T) {
	authboss.NewConfig()
	lock := Lock{}
	ctx := authboss.NewContext()

	if err := lock.AfterAuth(ctx); err != errUserMissing {
		t.Error("Expected an error because of missing user:", err)
	}

	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer
	ctx.User = authboss.Attributes{authboss.Cfg.PrimaryID: "john@john.com"}

	if err := lock.AfterAuth(ctx); err != nil {
		t.Error(err)
	}
	if storer.Users["john@john.com"][StoreAttemptNumber].(int) != 0 {
		t.Error("StoreAttemptNumber set incorrectly.")
	}
	if _, ok := storer.Users["john@john.com"][StoreAttemptTime].(time.Time); !ok {
		t.Error("StoreAttemptTime not set.")
	}
}

func TestAfterAuthFail_Lock(t *testing.T) {
	authboss.NewConfig()
	var old, current time.Time
	var ok bool

	ctx := authboss.NewContext()
	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer
	lock := Lock{}
	authboss.Cfg.LockWindow = 30 * time.Minute
	authboss.Cfg.LockAfter = 3

	email := "john@john.com"

	ctx.User = map[string]interface{}{authboss.Cfg.PrimaryID: email}

	old = time.Now().UTC().Add(-1 * time.Hour)

	for i := 0; i < 3; i++ {
		if lockedIntf, ok := storer.Users["john@john.com"][StoreLocked]; ok && lockedIntf.(bool) {
			t.Errorf("%d: User should not be locked.", i)
		}

		if err := lock.AfterAuthFail(ctx); err != nil {
			t.Error(err)
		}
		if val := storer.Users[email][StoreAttemptNumber].(int); val != i+1 {
			t.Errorf("%d: StoreAttemptNumber set incorrectly: %v", i, val)
		}
		if current, ok = storer.Users[email][StoreAttemptTime].(time.Time); !ok || old.After(current) {
			t.Error("%d: StoreAttemptTime not set correctly: %v", i, current)
		}

		current = old
	}

	if !storer.Users[email][StoreLocked].(bool) {
		t.Error("User should be locked.")
	}
	if val := storer.Users[email][StoreAttemptNumber].(int); val != 3 {
		t.Error("StoreAttemptNumber set incorrectly:", val)
	}
	if _, ok = storer.Users[email][StoreAttemptTime].(time.Time); !ok {
		t.Error("StoreAttemptTime not set correctly.")
	}
}

func TestAfterAuthFail_Reset(t *testing.T) {
	authboss.NewConfig()
	var old, current time.Time
	var ok bool

	ctx := authboss.NewContext()
	storer := mocks.NewMockStorer()
	lock := Lock{}
	authboss.Cfg.LockWindow = 30 * time.Minute
	authboss.Cfg.Storer = storer

	old = time.Now().UTC().Add(-time.Hour)

	email := "john@john.com"
	ctx.User = map[string]interface{}{
		authboss.Cfg.PrimaryID: email,
		StoreAttemptNumber:     2,
		StoreAttemptTime:       old,
		StoreLocked:            false,
	}

	lock.AfterAuthFail(ctx)
	if val := storer.Users[email][StoreAttemptNumber].(int); val != 0 {
		t.Error("StoreAttemptNumber set incorrectly:", val)
	}
	if current, ok = storer.Users[email][StoreAttemptTime].(time.Time); !ok || current.Before(old) {
		t.Error("StoreAttemptTime not set correctly.")
	}
	if locked := storer.Users[email][StoreLocked].(bool); locked {
		t.Error("StoreLocked not set correctly:", locked)
	}
}

func TestAfterAuthFail_Errors(t *testing.T) {
	authboss.NewConfig()
	lock := Lock{}
	ctx := authboss.NewContext()

	lock.AfterAuthFail(ctx)
	if _, ok := ctx.User[StoreAttemptNumber]; ok {
		t.Error("Expected nothing to be set, missing user.")
	}
}

func TestLock(t *testing.T) {
	authboss.NewConfig()
	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer
	lock := Lock{}

	email := "john@john.com"
	storer.Users[email] = map[string]interface{}{
		authboss.Cfg.PrimaryID: email,
		"password":             "password",
	}

	err := lock.Lock(email)
	if err != nil {
		t.Error(err)
	}

	if locked := storer.Users[email][StoreLocked].(bool); !locked {
		t.Error("User should be locked.")
	}
}

func TestUnlock(t *testing.T) {
	authboss.NewConfig()
	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer
	lock := Lock{}
	authboss.Cfg.LockWindow = 1 * time.Hour

	email := "john@john.com"
	storer.Users[email] = map[string]interface{}{
		authboss.Cfg.PrimaryID: email,
		"password":             "password",
		"locked":               true,
	}

	err := lock.Unlock(email)
	if err != nil {
		t.Error(err)
	}

	attemptTime := storer.Users[email][StoreAttemptTime].(time.Time)
	if attemptTime.After(time.Now().UTC().Add(-authboss.Cfg.LockWindow)) {
		t.Error("StoreLocked not set correctly:", attemptTime)
	}
	if number := storer.Users[email][StoreAttemptNumber].(int); number != 0 {
		t.Error("StoreLocked not set correctly:", number)
	}
	if locked := storer.Users[email][StoreLocked].(bool); locked {
		t.Error("User should not be locked.")
	}
}
