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
	// Validate makes the type validate itself and return
	// a list of validation errors.
	Validate() []error
}

// FieldError describes an error on a field
// Typically .Error() has both Name() and Err() together, hence the reason
// for separation.
type FieldError interface {
	error
	Name() string
	Err() error
}

// ErrorMap is a shortcut to change []error into ErrorList and call Map on it since
// this is a common operation.
func ErrorMap(e []error) map[string][]string {
	return ErrorList(e).Map()
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
