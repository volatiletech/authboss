package authboss

import (
	"bytes"
	"fmt"
)

type ErrorList []error

// FieldError represents an error that occurs during validation and is always
// attached to field on a form.
type FieldError struct {
	Name string
	Err  error
}

func (f FieldError) Error() string {
	return fmt.Sprintf("%s: %v", f.Name, f.Err)
}

// Error satisfies the error interface.
func (e ErrorList) Error() string {
	b := &bytes.Buffer{}
	first := true
	for _, err := range e {
		if first {
			first = false
		} else {
			b.WriteString(", ")
		}
		b.WriteString(err.Error())
	}
	return b.String()
}

// Validator is anything that can validate a string and provide a list of errors
// and describe its set of rules.
type Validator interface {
	Errors(in string) ErrorList
	Rules() []string
}
