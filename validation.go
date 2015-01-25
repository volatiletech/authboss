package authboss

import (
	"bytes"
	"fmt"
)

// Validator is anything that can validate a string and provide a list of errors
// and describe its set of rules.
type Validator interface {
	Field() string
	Errors(in string) ErrorList
	Rules() []string
}

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
			m[fieldErr.Name] = append(m[fieldErr.Name], fieldErr.Err.Error())
		}
	}

	return m
}

// FieldError represents an error that occurs during validation and is always
// attached to field on a form.
type FieldError struct {
	Name string
	Err  error
}

func (f FieldError) Error() string {
	return fmt.Sprintf("%s: %v", f.Name, f.Err)
}

// Validate validates a request using the given ruleset.
func (ctx *Context) Validate(ruleset []Validator) ErrorList {
	errList := make(ErrorList, 0)

	for _, validator := range ruleset {
		field := validator.Field()

		val, _ := ctx.FirstFormValue(field)
		if errs := validator.Errors(val); len(errs) > 0 {
			errList = append(errList, errs...)
		}
	}

	return errList
}
