package authboss

import (
	"context"
	"errors"
	"testing"
)

func TestEvents(t *testing.T) {
	t.Parallel()

	ab := New()
	afterCalled := false
	beforeCalled := false

	ab.Events.Before(EventRegister, func(ctx context.Context) (Interrupt, error) {
		beforeCalled = true
		return InterruptNone, nil
	})
	ab.Events.After(EventRegister, func(ctx context.Context) error {
		afterCalled = true
		return nil
	})

	if beforeCalled || afterCalled {
		t.Error("Neither should be called.")
	}

	interrupt, err := ab.Events.FireBefore(context.Background(), EventRegister)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if interrupt != InterruptNone {
		t.Error("It should not have been stopped.")
	}

	if !beforeCalled {
		t.Error("Expected before to have been called.")
	}
	if afterCalled {
		t.Error("Expected after not to be called.")
	}

	ab.Events.FireAfter(context.Background(), EventRegister)
	if !afterCalled {
		t.Error("Expected after to be called.")
	}
}

func TestCallbacksInterrupt(t *testing.T) {
	t.Parallel()

	ev := NewEvents()
	before1 := false
	before2 := false

	ev.Before(EventRegister, func(ctx context.Context) (Interrupt, error) {
		before1 = true
		return InterruptAccountLocked, nil
	})
	ev.Before(EventRegister, func(ctx context.Context) (Interrupt, error) {
		before2 = true
		return InterruptNone, nil
	})

	interrupt, err := ev.FireBefore(context.Background(), EventRegister)
	if err != nil {
		t.Error(err)
	}
	if interrupt != InterruptAccountLocked {
		t.Error("The interrupt signal was not account locked:", interrupt)
	}

	if !before1 {
		t.Error("Before1 should have been called.")
	}
	if before2 {
		t.Error("Before2 should not have been called.")
	}
}

func TestCallbacksBeforeErrors(t *testing.T) {
	t.Parallel()

	ev := NewEvents()
	before1 := false
	before2 := false

	errValue := errors.New("Problem occured")

	ev.Before(EventRegister, func(ctx context.Context) (Interrupt, error) {
		before1 = true
		return InterruptNone, errValue
	})
	ev.Before(EventRegister, func(ctx context.Context) (Interrupt, error) {
		before2 = true
		return InterruptNone, nil
	})

	interrupt, err := ev.FireBefore(context.Background(), EventRegister)
	if err != errValue {
		t.Error("Expected an error to come back.")
	}
	if interrupt != InterruptNone {
		t.Error("It should not have been stopped.")
	}

	if !before1 {
		t.Error("Before1 should have been called.")
	}
	if before2 {
		t.Error("Before2 should not have been called.")
	}
}

func TestCallbacksAfterErrors(t *testing.T) {
	t.Parallel()

	ev := NewEvents()
	after1 := false
	after2 := false

	errValue := errors.New("Problem occured")

	ev.After(EventRegister, func(ctx context.Context) error {
		after1 = true
		return errValue
	})
	ev.After(EventRegister, func(ctx context.Context) error {
		after2 = true
		return nil
	})

	err := ev.FireAfter(context.Background(), EventRegister)
	if err != errValue {
		t.Error("Expected an error to come back.")
	}

	if !after1 {
		t.Error("After1 should have been called.")
	}
	if after2 {
		t.Error("After2 should not have been called.")
	}
}

func TestEventString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ev  Event
		str string
	}{
		{EventRegister, "EventRegister"},
		{EventAuth, "EventAuth"},
		{EventOAuth, "EventOAuth"},
		{EventAuthFail, "EventAuthFail"},
		{EventOAuthFail, "EventOAuthFail"},
		{EventRecoverStart, "EventRecoverStart"},
		{EventRecoverEnd, "EventRecoverEnd"},
		{EventGetUser, "EventGetUser"},
		{EventGetUserSession, "EventGetUserSession"},
		{EventPasswordReset, "EventPasswordReset"},
	}

	for i, test := range tests {
		if got := test.ev.String(); got != test.str {
			t.Errorf("%d) Wrong string for Event(%d) expected: %v got: %s", i, test.ev, test.str, got)
		}
	}
}

func TestInterruptString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in  Interrupt
		str string
	}{
		{InterruptNone, "InterruptNone"},
		{InterruptAccountLocked, "InterruptAccountLocked"},
		{InterruptAccountNotConfirmed, "InterruptAccountNotConfirmed"},
		{InterruptSessionExpired, "InterruptSessionExpired"},
	}

	for i, test := range tests {
		if got := test.in.String(); got != test.str {
			t.Errorf("%d) Wrong string for Event(%d) expected: %v got: %s", i, test.in, test.str, got)
		}
	}
}
