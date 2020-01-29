package authboss

import (
	"context"
	"testing"
)

type testAssertionFailStorer struct{}

func (testAssertionFailStorer) Load(_ context.Context, _ string) (User, error) { return nil, nil }
func (testAssertionFailStorer) Save(_ context.Context, _ User) error           { return nil }

func TestStorageAssertions(t *testing.T) {
	t.Parallel()

	s := &mockServerStorer{}
	fs := testAssertionFailStorer{}

	paniced := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				paniced = true
			}
		}()

		EnsureCanCreate(s)
		EnsureCanConfirm(s)
		EnsureCanRecover(s)
		EnsureCanRemember(s)
		EnsureCanOAuth2(s)
	}()

	if paniced {
		t.Error("The mock storer should have included all interfaces and should not panic")
	}

	didPanic := func(f func()) (paniced bool) {
		defer func() {
			if r := recover(); r != nil {
				paniced = true
			}
		}()

		f()
		return paniced
	}

	if !didPanic(func() { EnsureCanCreate(fs) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { EnsureCanConfirm(fs) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { EnsureCanRecover(fs) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { EnsureCanRemember(fs) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { EnsureCanOAuth2(fs) }) {
		t.Error("should have panic'd")
	}
}
