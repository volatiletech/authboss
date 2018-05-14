package authboss

import "testing"

func TestOAuth2PIDs(t *testing.T) {
	t.Parallel()

	provider := "provider"
	uid := "uid"
	pid := MakeOAuth2PID(provider, uid)

	if pid != "oauth2;;provider;;uid" {
		t.Error("pid was wrong:", pid)
	}

	gotProvider, gotUID := ParseOAuth2PIDP(pid)
	if gotUID != uid {
		t.Error("uid was wrong:", gotUID)
	}
	if gotProvider != provider {
		t.Error("provider was wrong:", gotProvider)
	}

	notEnoughSegments, didntStartWithOAuth2 := false, false

	func() {
		defer func() {
			if r := recover(); r != nil {
				notEnoughSegments = true
			}
		}()

		_, _ = ParseOAuth2PIDP("nope")
	}()

	if !notEnoughSegments {
		t.Error("expected a panic when there's not enough segments")
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				didntStartWithOAuth2 = true
			}
		}()

		_, _ = ParseOAuth2PIDP("notoauth2;;but;;restisgood")
	}()

	if !didntStartWithOAuth2 {
		t.Error("expected a panic when the pid doesn't start with oauth2")
	}
}

type testAssertionFailUser struct{}

func (testAssertionFailUser) GetPID() string { return "" }
func (testAssertionFailUser) PutPID(string)  {}

func TestUserAssertions(t *testing.T) {
	t.Parallel()

	u := &mockUser{}
	fu := testAssertionFailUser{}

	paniced := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				paniced = true
			}
		}()

		MustBeAuthable(u)
		MustBeConfirmable(u)
		MustBeLockable(u)
		MustBeOAuthable(u)
		MustBeRecoverable(u)
	}()

	if paniced {
		t.Error("The mock user should have included all interfaces and should not panic")
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

	if !didPanic(func() { MustBeAuthable(fu) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { MustBeConfirmable(fu) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { MustBeLockable(fu) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { MustBeOAuthable(fu) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { MustBeRecoverable(fu) }) {
		t.Error("should have panic'd")
	}
}
