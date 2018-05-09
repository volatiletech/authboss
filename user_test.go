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
