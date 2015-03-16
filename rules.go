package authboss

import (
	"errors"
	"fmt"
	"regexp"
	"unicode"
)

var blankRegex = regexp.MustCompile(`^\s*$`)

// Rules defines a ruleset by which a string can be validated.
type Rules struct {
	// FieldName is the name of the field this is intended to validate.
	FieldName string
	// MatchError describes the MustMatch regexp to a user.
	Required             bool
	MatchError           string
	MustMatch            *regexp.Regexp
	MinLength, MaxLength int
	MinLetters           int
	MinLower, MinUpper   int
	MinNumeric           int
	MinSymbols           int
	AllowWhitespace      bool
}

// Field names the field this ruleset applies to.
func (r Rules) Field() string {
	return r.FieldName
}

// Errors returns an array of errors for each validation error that
// is present in the given string. Returns nil if there are no errors.
func (r Rules) Errors(toValidate string) ErrorList {
	errs := make(ErrorList, 0)

	ln := len(toValidate)
	if r.Required && (ln == 0 || blankRegex.MatchString(toValidate)) {
		return append(errs, FieldError{r.FieldName, errors.New("Cannot be blank")})
	}

	if r.MustMatch != nil {
		if !r.MustMatch.MatchString(toValidate) {
			errs = append(errs, FieldError{r.FieldName, errors.New(r.MatchError)})
		}
	}

	if (r.MinLength > 0 && ln < r.MinLength) || (r.MaxLength > 0 && ln > r.MaxLength) {
		errs = append(errs, FieldError{r.FieldName, errors.New(r.lengthErr())})
	}

	upper, lower, numeric, symbols, whitespace := tallyCharacters(toValidate)
	if upper+lower < r.MinLetters {
		errs = append(errs, FieldError{r.FieldName, errors.New(r.charErr())})
	}
	if upper < r.MinUpper {
		errs = append(errs, FieldError{r.FieldName, errors.New(r.upperErr())})
	}
	if upper < r.MinLower {
		errs = append(errs, FieldError{r.FieldName, errors.New(r.lowerErr())})
	}
	if numeric < r.MinNumeric {
		errs = append(errs, FieldError{r.FieldName, errors.New(r.numericErr())})
	}
	if symbols < r.MinSymbols {
		errs = append(errs, FieldError{r.FieldName, errors.New(r.symbolErr())})
	}
	if !r.AllowWhitespace && whitespace > 0 {
		errs = append(errs, FieldError{r.FieldName, errors.New("No whitespace permitted")})
	}

	if len(errs) == 0 {
		return nil
	}

	return errs
}

// IsValid checks toValidate to make sure it's valid according to the rules.
func (r Rules) IsValid(toValidate string) bool {
	return nil == r.Errors(toValidate)
}

// Rules returns an array of strings describing the rules.
func (r Rules) Rules() []string {
	var rules []string

	if r.MustMatch != nil {
		rules = append(rules, r.MatchError)
	}

	if e := r.lengthErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.charErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.upperErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.lowerErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.numericErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.symbolErr(); len(e) > 0 {
		rules = append(rules, e)
	}

	return rules
}

func (r Rules) lengthErr() (err string) {
	switch {
	case r.MinLength > 0 && r.MaxLength > 0:
		err = fmt.Sprintf("Must be between %d and %d characters", r.MinLength, r.MaxLength)
	case r.MinLength > 0:
		err = fmt.Sprintf("Must be at least %d characters", r.MinLength)
	case r.MaxLength > 0:
		err = fmt.Sprintf("Must be at most %d characters", r.MaxLength)
	}

	return err
}

func (r Rules) charErr() (err string) {
	if r.MinLetters > 0 {
		err = fmt.Sprintf("Must contain at least %d letters", r.MinLetters)
	}
	return err
}

func (r Rules) upperErr() (err string) {
	if r.MinUpper > 0 {
		err = fmt.Sprintf("Must contain at least %d uppercase letters", r.MinUpper)
	}
	return err
}

func (r Rules) lowerErr() (err string) {
	if r.MinLower > 0 {
		err = fmt.Sprintf("Must contain at least %d lowercase letters", r.MinLower)
	}
	return err
}

func (r Rules) numericErr() (err string) {
	if r.MinNumeric > 0 {
		err = fmt.Sprintf("Must contain at least %d numbers", r.MinNumeric)
	}
	return err
}

func (r Rules) symbolErr() (err string) {
	if r.MinSymbols > 0 {
		err = fmt.Sprintf("Must contain at least %d symbols", r.MinSymbols)
	}
	return err
}

func tallyCharacters(s string) (upper, lower, numeric, symbols, whitespace int) {
	for _, c := range s {
		switch {
		case unicode.IsLetter(c):
			if unicode.IsUpper(c) {
				upper++
			} else {
				lower++
			}
		case unicode.IsDigit(c):
			numeric++
		case unicode.IsSpace(c):
			whitespace++
		default:
			symbols++
		}
	}

	return upper, lower, numeric, symbols, whitespace
}
