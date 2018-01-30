package defaults

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	req := mocks.Request("POST", "username", "john", "email", "john@john.com")

	validator := HTTPFormValidator{
		Ruleset: []authboss.FieldValidator{
			mocks.FieldValidator{
				FieldName: "username",
				Errs:      authboss.ErrorList{FieldError{"username", errors.New("must be longer than 4")}},
			},
			mocks.FieldValidator{
				FieldName: "missing_field",
				Errs:      authboss.ErrorList{FieldError{"missing_field", errors.New("Expected field to exist")}},
			},
			mocks.FieldValidator{
				FieldName: "email", Errs: nil,
			},
		},
	}

	errList := validator.Validate(req)

	errs := errList.Map()
	if errs["username"][0] != "must be longer than 4" {
		t.Error("Expected a different error for username:", errs["username"][0])
	}
	if errs["missing_field"][0] != "Expected field to exist" {
		t.Error("Expected a different error for missing_field:", errs["missing_field"][0])
	}
	if _, ok := errs["email"]; ok {
		t.Error("Expected no errors for email.")
	}
}

func TestValidate_Confirm(t *testing.T) {
	t.Parallel()

	validator := HTTPFormValidator{
		ConfirmFields: []string{"username", "confirmUsername"},
	}

	req := mocks.Request("POST", "username", "john", "confirmUsername", "johnny")
	errs := validator.Validate(req).Map()
	if errs["confirmUsername"][0] != "Does not match username" {
		t.Error("Expected a different error for confirmUsername:", errs["confirmUsername"][0])
	}

	req = mocks.Request("POST", "username", "john", "confirmUsername", "john")
	errs = validator.Validate(req).Map()
	if len(errs) != 0 {
		t.Error("Expected no errors:", errs)
	}

	validator = HTTPFormValidator{
		ConfirmFields: []string{"username"},
	}

	req = mocks.Request("POST", "username", "john", "confirmUsername", "john")
	errs = validator.Validate(req).Map()
	if len(errs) != 0 {
		t.Error("Expected no errors:", errs)
	}
}
