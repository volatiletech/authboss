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
			Rules{FieldName: "email"},
			"",
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
		MinNumeric:      4,
		MinSymbols:      5,
		AllowWhitespace: false,
	}

	rules := r.Rules()

	mustFind := []string{
		"Must adhere to this regexp",
		"Must be between 1 and 2 characters",
		"Must contain at least 3 letters",
		"Must contain at least 4 numbers",
		"Must contain at least 5 symbols",
	}

	for i, toFind := range mustFind {
		if rules[i] != toFind {
			t.Error("Expected:", toFind, "got:", rules[i])
		}
	}
}

func TestRules_IsValid(t *testing.T) {
	t.Parallel()

	r := Rules{FieldName: "email"}
	if r.IsValid("") {
		t.Error("It should not be valid.")
	}

	if !r.IsValid("joe@joe.com") {
		t.Error("It should be valid.")
	}
}

func TestTallyCharacters(t *testing.T) {
	t.Parallel()

	c, n, s, w := tallyCharacters("123abcDEF@#$%^*   ")
	if c != 6 {
		t.Error("Number of chars:", c)
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
