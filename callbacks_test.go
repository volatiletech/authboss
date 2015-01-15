package authboss

import (
	"errors"
	"testing"
)

func TestCallbacks(t *testing.T) {
	afterCalled := false
	beforeCalled := false
	c := NewCallbacks()

	c.Before(EventRegister, func(ctx *Context) error {
		beforeCalled = true
		return nil
	})
	c.After(EventRegister, func(ctx *Context) {
		afterCalled = true
	})

	if beforeCalled || afterCalled {
		t.Error("Neither should be called.")
	}

	err := c.FireBefore(EventRegister, NewContext())
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if !beforeCalled {
		t.Error("Expected before to have been called.")
	}
	if afterCalled {
		t.Error("Expected after not to be called.")
	}

	c.FireAfter(EventRegister, NewContext())
	if !afterCalled {
		t.Error("Expected after to be called.")
	}
}

func TestCallbacksInterrupt(t *testing.T) {
	before1 := false
	before2 := false
	c := NewCallbacks()

	errValue := errors.New("Problem occured.")

	c.Before(EventRegister, func(ctx *Context) error {
		before1 = true
		return errValue
	})
	c.Before(EventRegister, func(ctx *Context) error {
		before2 = true
		return nil
	})

	err := c.FireBefore(EventRegister, NewContext())
	if err != errValue {
		t.Error("Expected an error to come back.")
	}

	if !before1 {
		t.Error("Before1 should have been called.")
	}
	if before2 {
		t.Error("Before2 should not have been called.")
	}
}
