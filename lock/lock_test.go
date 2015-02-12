package lock

import (
	"io/ioutil"
	"testing"
	"time"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

func TestStorage(t *testing.T) {
	storage := L.Storage()
	if _, ok := storage[UserAttemptNumber]; !ok {
		t.Error("Expected attempt number storage option.")
	}
	if _, ok := storage[UserAttemptTime]; !ok {
		t.Error("Expected attempt number time option.")
	}
}

func TestBeforeAuth(t *testing.T) {
	ctx := authboss.NewContext()
	L.logger = ioutil.Discard

	if nil != L.BeforeAuth(ctx) {
		t.Error("Expected it to break early.")
	}

	if err := L.BeforeAuth(ctx); err != nil {
		t.Error(err)
	}

	ctx.User = authboss.Attributes{"locked": true}

	if err := L.BeforeAuth(ctx); err != ErrLocked {
		t.Error("Expected an ErrLocked:", err)
	}
}

func TestAfterAuth(t *testing.T) {
	lock := Lock{}
	lock.logger = ioutil.Discard
	ctx := authboss.NewContext()

	lock.AfterAuth(ctx)
	if _, ok := ctx.User[UserAttemptNumber]; ok {
		t.Error("Expected nothing to be set, missing user.")
	}

	ctx.User = map[string]interface{}{"otherattribute": "somevalue"}
	lock.AfterAuth(ctx)
	if _, ok := ctx.User[UserAttemptNumber]; ok {
		t.Error("Expected username not present to stop this assignment.")
	}

	ctx.User["username"] = 5
	lock.AfterAuth(ctx)
	if _, ok := ctx.User[UserAttemptNumber]; ok {
		t.Error("Expected username wrong type stop this assignment.")
	}

	storer := mocks.NewMockStorer()
	lock.storer = storer
	ctx.User["username"] = "username"
	lock.AfterAuth(ctx)

	if storer.Users["username"][UserAttemptNumber].(int) != 0 {
		t.Error("UserAttemptNumber set incorrectly.")
	}
	if _, ok := storer.Users["username"][UserAttemptTime].(time.Time); !ok {
		t.Error("UserAttemptTime not set.")
	}
}

func TestAfterAuthFail_Lock(t *testing.T) {
	var old, current time.Time
	var ok bool

	ctx := authboss.NewContext()
	storer := mocks.NewMockStorer()
	lock := Lock{}
	lock.logger = ioutil.Discard
	lock.storer = storer
	lock.window = 30 * time.Minute
	lock.attempts = 3

	ctx.User = map[string]interface{}{"username": "username"}

	old = time.Now().UTC().Add(-1 * time.Hour)

	for i := 0; i < 3; i++ {
		if lockedIntf, ok := storer.Users["username"][UserLocked]; ok && lockedIntf.(bool) {
			t.Errorf("%d: User should not be locked.", i)
		}

		lock.AfterAuthFail(ctx)
		if val := storer.Users["username"][UserAttemptNumber].(int); val != i+1 {
			t.Errorf("%d: UserAttemptNumber set incorrectly: %v", i, val)
		}
		if current, ok = storer.Users["username"][UserAttemptTime].(time.Time); !ok || old.After(current) {
			t.Error("%d: UserAttemptTime not set correctly: %v", i, current)
		}

		current = old
	}

	if !storer.Users["username"][UserLocked].(bool) {
		t.Error("User should be locked.")
	}
	if val := storer.Users["username"][UserAttemptNumber].(int); val != 3 {
		t.Error("UserAttemptNumber set incorrectly:", val)
	}
	if _, ok = storer.Users["username"][UserAttemptTime].(time.Time); !ok {
		t.Error("UserAttemptTime not set correctly.")
	}
}

func TestAfterAuthFail_Reset(t *testing.T) {
	var old, current time.Time
	var ok bool

	ctx := authboss.NewContext()
	storer := mocks.NewMockStorer()
	lock := Lock{}
	lock.window = 30 * time.Minute
	lock.logger = ioutil.Discard
	lock.storer = storer

	old = time.Now().UTC().Add(-time.Hour)

	ctx.User = map[string]interface{}{
		"username":        "username",
		UserAttemptNumber: 2,
		UserAttemptTime:   old,
		UserLocked:        false,
	}

	lock.AfterAuthFail(ctx)
	if val := storer.Users["username"][UserAttemptNumber].(int); val != 0 {
		t.Error("UserAttemptNumber set incorrectly:", val)
	}
	if current, ok = storer.Users["username"][UserAttemptTime].(time.Time); !ok || current.Before(old) {
		t.Error("UserAttemptTime not set correctly.")
	}
	if locked := storer.Users["username"][UserLocked].(bool); locked {
		t.Error("UserLocked not set correctly:", locked)
	}
}

func TestAfterAuthFail_Errors(t *testing.T) {
	lock := Lock{}
	lock.logger = ioutil.Discard
	ctx := authboss.NewContext()

	lock.AfterAuthFail(ctx)
	if _, ok := ctx.User[UserAttemptNumber]; ok {
		t.Error("Expected nothing to be set, missing user.")
	}

	ctx.User = map[string]interface{}{"otherattribute": "somevalue"}
	lock.AfterAuthFail(ctx)
	if _, ok := ctx.User[UserAttemptNumber]; ok {
		t.Error("Expected username not present to stop this assignment.")
	}

	ctx.User["username"] = 5
	lock.AfterAuthFail(ctx)
	if _, ok := ctx.User[UserAttemptNumber]; ok {
		t.Error("Expected username wrong type stop this assignment.")
	}
}

func TestLock(t *testing.T) {
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

	if locked := storer.Users["username"][UserLocked].(bool); !locked {
		t.Error("User should be locked.")
	}
}

func TestUnlock(t *testing.T) {
	storer := mocks.NewMockStorer()
	lock := Lock{}
	lock.window = 1 * time.Hour

	storer.Users["username"] = map[string]interface{}{
		"username": "username",
		"password": "password",
		"locked":   true,
	}

	err := lock.Unlock("username", storer)
	if err != nil {
		t.Error(err)
	}

	attemptTime := storer.Users["username"][UserAttemptTime].(time.Time)
	if attemptTime.After(time.Now().UTC().Add(-lock.window)) {
		t.Error("UserLocked not set correctly:", attemptTime)
	}
	if number := storer.Users["username"][UserAttemptNumber].(int); number != 0 {
		t.Error("UserLocked not set correctly:", number)
	}
	if locked := storer.Users["username"][UserLocked].(bool); locked {
		t.Error("User should not be locked.")
	}
}
