package authboss

import (
	"regexp"
	"testing"
)

func TestRules_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Rules Rules
		In    string
		Error string
	}{
		{
			Rules{FieldName: "email", Required: true},
			"",
			"email: Cannot be blank",
		},
		{
			Rules{FieldName: "email", Required: true},
			"   \t\t\n   ",
			"email: Cannot be blank",
		},
		{
			Rules{FieldName: "email", MatchError: "Regexp must match!", MustMatch: regexp.MustCompile("abc")},
			"hello",
			"email: Regexp must match!",
		},
		{
			Rules{FieldName: "email", MinLength: 5},
			"hi",
			"email: Must be at least 5 characters",
		},
		{
			Rules{FieldName: "email", MaxLength: 3},
			"hello",
			"email: Must be at most 3 characters",
		},
		{
			Rules{FieldName: "email", MinLength: 3, MaxLength: 5},
			"hi",
			"email: Must be between 3 and 5 characters",
		},
		{
			Rules{FieldName: "email", MinLetters: 5},
			"13345",
			"email: Must contain at least 5 letters",
		},
		{
			Rules{FieldName: "email", MinUpper: 5},
			"hi",
			"email: Must contain at least 5 uppercase letters",
		},
		{
			Rules{FieldName: "email", MinLower: 5},
			"hi",
			"email: Must contain at least 5 lowercase letters",
		},
		{
			Rules{FieldName: "email", MinSymbols: 5},
			"hi",
			"email: Must contain at least 5 symbols",
		},
		{
			Rules{FieldName: "email", MinNumeric: 5},
			"hi",
			"email: Must contain at least 5 numbers",
		},
		{
			Rules{FieldName: "email"},
			"hi whitespace",
			"email: No whitespace permitted",
		},
	}

	for i, test := range tests {
		i = i + 1

		err := test.Rules.Errors(test.In)
		if err == nil {
			t.Errorf("(%d) Wanted: %q", i, test.Error)
			continue
		}

		if e := err.Error(); e != test.Error {
			t.Errorf("(%d) The error was wrong: %q", i, e)
		}
	}
}

func TestRules_Rules(t *testing.T) {
	t.Parallel()

	r := Rules{
		FieldName:       "email",
		MatchError:      "Must adhere to this regexp",
		MustMatch:       regexp.MustCompile(""),
		MinLength:       1,
		MaxLength:       2,
		MinLetters:      3,
		MinUpper:        4,
		MinLower:        5,
		MinNumeric:      6,
		MinSymbols:      7,
		AllowWhitespace: false,
	}

	rules := r.Rules()

	mustFind := []string{
		"Must adhere to this regexp",
		"Must be between 1 and 2 characters",
		"Must contain at least 3 letters",
		"Must contain at least 4 uppercase letters",
		"Must contain at least 5 lowercase letters",
		"Must contain at least 6 numbers",
		"Must contain at least 7 symbols",
	}

	for i, toFind := range mustFind {
		if rules[i] != toFind {
			t.Error("Expected:", toFind, "got:", rules[i])
		}
	}
}

func TestRules_IsValid(t *testing.T) {
	t.Parallel()

	r := Rules{FieldName: "email", Required: true}
	if r.IsValid("") {
		t.Error("It should not be valid.")
	}

	if !r.IsValid("joe@joe.com") {
		t.Error("It should be valid.")
	}
}

func TestTallyCharacters(t *testing.T) {
	t.Parallel()

	u, l, n, s, w := tallyCharacters("123abcDEF@#$%^*   ")
	if u != 3 {
		t.Error("Number of upper:", u)
	}
	if l != 3 {
		t.Error("Number of lower:", l)
	}
	if n != 3 {
		t.Error("Number of numerics:", n)
	}
	if s != 6 {
		t.Error("Number of symbols:", s)
	}
	if w != 3 {
		t.Error("Number of whitespace:", w)
	}
}
