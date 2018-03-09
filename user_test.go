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

	gotProvider, gotUID := ParseOAuth2PID(pid)
	if gotUID != uid {
		t.Error("uid was wrong:", gotUID)
	}
	if gotProvider != provider {
		t.Error("provider was wrong:", gotProvider)
	}
}
