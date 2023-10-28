package authboss

import (
	"encoding/base64"
	"testing"
)

func TestCredsGenerator(t *testing.T) {
	t.Parallel()

	credsGenerator := NewSha512CredsGenerator()

	selector, verifier, tokenEncoded, err := credsGenerator.GenerateCreds()
	if err != nil {
		t.Error(err)
	}

	// let's decode the token
	tokenBytes, err := base64.URLEncoding.DecodeString(tokenEncoded)
	token := string(tokenBytes)

	if len(token) != credsGenerator.TokenSize() {
		t.Error("token size is invalid", len(token))
	}

	selectorBytes, verifierBytes := credsGenerator.ParseToken(token)

	// encode back and verify

	selectorParsed := base64.StdEncoding.EncodeToString(selectorBytes[:])
	verifierParsed := base64.StdEncoding.EncodeToString(verifierBytes[:])

	if selectorParsed != selector {
		t.Error("selector generated wrong", selector, selectorParsed)
	}

	if verifierParsed != verifier {
		t.Error("verifier generated wrong", verifier, verifierParsed)
	}
}
