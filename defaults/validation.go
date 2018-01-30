package defaults

import (
	"fmt"
	"net/http"

	"github.com/volatiletech/authboss"
)

// HTTPFormValidator validates HTTP post type inputs
type HTTPFormValidator struct {
	Ruleset       []authboss.FieldValidator
	ConfirmFields []string
}

// Validate validates a request using the given ruleset.
func (h HTTPFormValidator) Validate(r *http.Request) authboss.ErrorList {
	var errList authboss.ErrorList

	for _, fieldValidator := range h.Ruleset {
		field := fieldValidator.Field()

		val := r.FormValue(field)
		if errs := fieldValidator.Errors(val); len(errs) > 0 {
			errList = append(errList, errs...)
		}
	}

	for i := 0; i < len(h.ConfirmFields)-1; i += 2 {
		fmt.Println(h.ConfirmFields)
		main := r.FormValue(h.ConfirmFields[i])
		if len(main) == 0 {
			continue
		}

		confirm := r.FormValue(h.ConfirmFields[i+1])
		if len(confirm) == 0 || main != confirm {
			errList = append(errList, FieldError{h.ConfirmFields[i+1], fmt.Errorf("Does not match %s", h.ConfirmFields[i])})
		}
	}

	return errList
}

// FieldError represents an error that occurs during validation and is always
// attached to field on a form.
type FieldError struct {
	FieldName string
	FieldErr  error
}

// NewFieldError literally only exists because of poor name planning
// where name and err can't be exported on the struct due to the method names
func NewFieldError(name string, err error) FieldError {
	return FieldError{FieldName: name, FieldErr: err}
}

// Name of the field the error is about
func (f FieldError) Name() string {
	return f.FieldName
}

// Err for the field
func (f FieldError) Err() error {
	return f.FieldErr
}

// Error in string form
func (f FieldError) Error() string {
	return fmt.Sprintf("%s: %v", f.FieldName, f.FieldErr)
}
