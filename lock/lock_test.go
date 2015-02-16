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

	if err := L.BeforeAuth(ctx); err == nil {
		t.Error("Want death because user not loaded:", err)
	}

	ctx.User = authboss.Attributes{"locked": true}

	if err := L.BeforeAuth(ctx); err != ErrLocked {
		t.Error("Expected an ErrLocked:", err)
	}
}

func TestAfterAuth(t *testing.T) {
	authboss.NewConfig()
	lock := Lock{}
	ctx := authboss.NewContext()

	lock.AfterAuth(ctx)
	if _, ok := ctx.User[StoreAttemptNumber]; ok {
		t.Error("Expected nothing to be set, missing user.")
	}

	ctx.User = map[string]interface{}{"otherattribute": "somevalue"}
	lock.AfterAuth(ctx)
	if _, ok := ctx.User[StoreAttemptNumber]; ok {
		t.Error("Expected username not present to stop this assignment.")
	}

	ctx.User["username"] = 5
	lock.AfterAuth(ctx)
	if _, ok := ctx.User[StoreAttemptNumber]; ok {
		t.Error("Expected username wrong type stop this assignment.")
	}

	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer
	ctx.User["username"] = "username"
	lock.AfterAuth(ctx)

	if storer.Users["username"][StoreAttemptNumber].(int) != 0 {
		t.Error("StoreAttemptNumber set incorrectly.")
	}
	if _, ok := storer.Users["username"][StoreAttemptTime].(time.Time); !ok {
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

	ctx.User = map[string]interface{}{"username": "username"}

	old = time.Now().UTC().Add(-1 * time.Hour)

	for i := 0; i < 3; i++ {
		if lockedIntf, ok := storer.Users["username"][StoreLocked]; ok && lockedIntf.(bool) {
			t.Errorf("%d: User should not be locked.", i)
		}

		lock.AfterAuthFail(ctx)
		if val := storer.Users["username"][StoreAttemptNumber].(int); val != i+1 {
			t.Errorf("%d: StoreAttemptNumber set incorrectly: %v", i, val)
		}
		if current, ok = storer.Users["username"][StoreAttemptTime].(time.Time); !ok || old.After(current) {
			t.Error("%d: StoreAttemptTime not set correctly: %v", i, current)
		}

		current = old
	}

	if !storer.Users["username"][StoreLocked].(bool) {
		t.Error("User should be locked.")
	}
	if val := storer.Users["username"][StoreAttemptNumber].(int); val != 3 {
		t.Error("StoreAttemptNumber set incorrectly:", val)
	}
	if _, ok = storer.Users["username"][StoreAttemptTime].(time.Time); !ok {
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

	ctx.User = map[string]interface{}{
		"username":         "username",
		StoreAttemptNumber: 2,
		StoreAttemptTime:   old,
		StoreLocked:        false,
	}

	lock.AfterAuthFail(ctx)
	if val := storer.Users["username"][StoreAttemptNumber].(int); val != 0 {
		t.Error("StoreAttemptNumber set incorrectly:", val)
	}
	if current, ok = storer.Users["username"][StoreAttemptTime].(time.Time); !ok || current.Before(old) {
		t.Error("StoreAttemptTime not set correctly.")
	}
	if locked := storer.Users["username"][StoreLocked].(bool); locked {
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

	ctx.User = map[string]interface{}{"otherattribute": "somevalue"}
	lock.AfterAuthFail(ctx)
	if _, ok := ctx.User[StoreAttemptNumber]; ok {
		t.Error("Expected username not present to stop this assignment.")
	}

	ctx.User["username"] = 5
	lock.AfterAuthFail(ctx)
	if _, ok := ctx.User[StoreAttemptNumber]; ok {
		t.Error("Expected username wrong type stop this assignment.")
	}
}

func TestLock(t *testing.T) {
	authboss.NewConfig()
	storer := mocks.NewMockStorer()
	lock := Lock{}

	storer.Users["username"] = map[string]interface{}{
		"username": "username",
		"password": "password",
	}

	err := lock.Lock("username", storer)
	if err != nil {
		t.Error(err)
	}

	if locked := storer.Users["username"][StoreLocked].(bool); !locked {
		t.Error("User should be locked.")
	}
}

func TestUnlock(t *testing.T) {
	authboss.NewConfig()
	storer := mocks.NewMockStorer()
	lock := Lock{}
	authboss.Cfg.LockWindow = 1 * time.Hour

	storer.Users["username"] = map[string]interface{}{
		"username": "username",
		"password": "password",
		"locked":   true,
	}

	err := lock.Unlock("username", storer)
	if err != nil {
		t.Error(err)
	}

	attemptTime := storer.Users["username"][StoreAttemptTime].(time.Time)
	if attemptTime.After(time.Now().UTC().Add(-authboss.Cfg.LockWindow)) {
		t.Error("StoreLocked not set correctly:", attemptTime)
	}
	if number := storer.Users["username"][StoreAttemptNumber].(int); number != 0 {
		t.Error("StoreLocked not set correctly:", number)
	}
	if locked := storer.Users["username"][StoreLocked].(bool); locked {
		t.Error("User should not be locked.")
	}
}
