package totp2fa

import (
	"regexp"
	"strings"
	"testing"
)

func TestGenerateRecoveryCodes(t *testing.T) {
	t.Parallel()

	codes, err := generateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}

	if len(codes) != 10 {
		t.Error("it should create 10 codes, got:", len(codes))
	}

	rgx := regexp.MustCompile(`^[0-9a-z]{5}-[0-9a-z]{5}$`)
	for _, c := range codes {
		if !rgx.MatchString(c) {
			t.Errorf("code %s did not match regexp", c)
		}
	}
}

func TestHashRecoveryCodes(t *testing.T) {
	t.Parallel()

	codes, err := generateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}

	if len(codes) != 10 {
		t.Error("it should create 10 codes, got:", len(codes))
	}

	cryptedCodes, err := bcryptRecoveryCodes(codes)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range cryptedCodes {
		if !strings.HasPrefix(c, "$2a$10$") {
			t.Error("code did not look like bcrypt:", c)
		}
	}
}

func TestUseRecoveryCode(t *testing.T) {
	t.Parallel()

	codes, err := generateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}

	if len(codes) != 10 {
		t.Error("it should create 10 codes, got:", len(codes))
	}

	cryptedCodes, err := bcryptRecoveryCodes(codes)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range cryptedCodes {
		if !strings.HasPrefix(c, "$2a$10$") {
			t.Error("code did not look like bcrypt:", c)
		}
	}

	remaining, ok := useRecoveryCode(cryptedCodes, codes[4])
	if !ok {
		t.Error("should have used a code")
	}

	if want, got := len(cryptedCodes)-1, len(remaining); want != got {
		t.Error("want:", want, "got:", got)
	}

	if cryptedCodes[4] == remaining[4] {
		t.Error("it should have used number 4")
	}

	remaining, ok = useRecoveryCode(remaining, codes[0])
	if !ok {
		t.Error("should have used a code")
	}

	if want, got := len(cryptedCodes)-2, len(remaining); want != got {
		t.Error("want:", want, "got:", got)
	}

	if cryptedCodes[0] == remaining[0] {
		t.Error("it should have used number 0")
	}

	remaining, ok = useRecoveryCode(remaining, codes[len(codes)-1])
	if !ok {
		t.Error("should have used a code")
	}

	if want, got := len(cryptedCodes)-3, len(remaining); want != got {
		t.Error("want:", want, "got:", got)
	}

	if cryptedCodes[len(cryptedCodes)-1] == remaining[len(remaining)-1] {
		t.Error("it should have used number 0")
	}
}
