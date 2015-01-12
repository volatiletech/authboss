package authboss

import "testing"

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
