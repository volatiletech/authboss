package defaults

import "testing"

func TestSMTPMailer(t *testing.T) {
	t.Skip("must implement test against real smtp servers here")
}

func TestSMTPMailerPanic(t *testing.T) {
	t.Parallel()

	_ = NewSMTPMailer("server", nil)

	recovered := false
	defer func() {
		recovered = recover() != nil
	}()

	NewSMTPMailer("", nil)

	if !recovered {
		t.Error("Should have panicked.")
	}
}
