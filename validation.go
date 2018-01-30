package authboss

import (
	"bytes"
)

const (
	// ConfirmPrefix is prepended to names of confirm fields.
	ConfirmPrefix = "confirm_"
)

// Validator takes a form name and a set of inputs and returns any validation errors
// for the inputs.
type Validator interface {
	// Validate inputs from the named form
	Validate(name string, fieldValues map[string]string) []error
}

// FieldValidator is anything that can validate a string and provide a list of errors
// and describe its set of rules.
type FieldValidator interface {
	Field() string
	Errors(in string) []error
	Rules() []string
}

// FieldError describes an error on a field
type FieldError interface {
	Name() string
	Err() error
}

// ErrorList is simply a slice of errors with helpers.
type ErrorList []error

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

// Map groups errors by their field name
func (e ErrorList) Map() map[string][]string {
	m := make(map[string][]string)

	for _, err := range e {
		fieldErr, ok := err.(FieldError)
		if !ok {
			m[""] = append(m[""], err.Error())
		} else {
			name, err := fieldErr.Name(), fieldErr.Err()
			m[name] = append(m[name], err.Error())
		}
	}

	return m
}
