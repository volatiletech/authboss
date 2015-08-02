package authboss

import (
	"errors"
	"testing"
)

func TestErrorList_Error(t *testing.T) {
	t.Parallel()

	errList := ErrorList{errors.New("one"), errors.New("two")}
	if e := errList.Error(); e != "one, two" {
		t.Error("Wrong value for error:", e)
	}
}

func TestErrorList_Map(t *testing.T) {
	t.Parallel()

	errNotLong := "not long enough"
	errEmail := "should be an email"
	errAsploded := "asploded"

	errList := ErrorList{
		FieldError{StoreUsername, errors.New(errNotLong)},
		FieldError{StoreUsername, errors.New(errEmail)},
		FieldError{StorePassword, errors.New(errNotLong)},
		errors.New(errAsploded),
	}

	m := errList.Map()
	if len(m) != 3 {
		t.Error("Wrong number of fields:", len(m))
	}

	usernameErrs := m[StoreUsername]
	if len(usernameErrs) != 2 {
		t.Error("Wrong number of username errors:", len(usernameErrs))
	}
	if usernameErrs[0] != errNotLong {
		t.Error("Wrong username error at 0:", usernameErrs[0])
	}
	if usernameErrs[1] != errEmail {
		t.Error("Wrong username error at 1:", usernameErrs[1])
	}

	passwordErrs := m[StorePassword]
	if len(passwordErrs) != 1 {
		t.Error("Wrong number of password errors:", len(passwordErrs))
	}
	if passwordErrs[0] != errNotLong {
		t.Error("Wrong password error at 0:", passwordErrs[0])
	}

	unknownErrs := m[""]
	if len(unknownErrs) != 1 {
		t.Error("Wrong number of unkown errors:", len(unknownErrs))
	}
	if unknownErrs[0] != errAsploded {
		t.Error("Wrong unkown error at 0:", unknownErrs[0])
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	req := mockRequest(StoreUsername, "john", StoreEmail, "john@john.com")

	errList := Validate(req, []Validator{
		mockValidator{
			FieldName: StoreUsername,
			Errs:      ErrorList{FieldError{StoreUsername, errors.New("must be longer than 4")}},
		},
		mockValidator{
			FieldName: "missing_field",
			Errs:      ErrorList{FieldError{"missing_field", errors.New("Expected field to exist.")}},
		},
		mockValidator{
			FieldName: StoreEmail, Errs: nil,
		},
	})

	errs := errList.Map()
	if errs[StoreUsername][0] != "must be longer than 4" {
		t.Error("Expected a different error for username:", errs[StoreUsername][0])
	}
	if errs["missing_field"][0] != "Expected field to exist." {
		t.Error("Expected a different error for missing_field:", errs["missing_field"][0])
	}
	if _, ok := errs[StoreEmail]; ok {
		t.Error("Expected no errors for email.")
	}
}

func TestValidate_Confirm(t *testing.T) {
	t.Parallel()

	req := mockRequest(StoreUsername, "john", "confirmUsername", "johnny")
	errs := Validate(req, nil, StoreUsername, "confirmUsername").Map()
	if errs["confirmUsername"][0] != "Does not match username" {
		t.Error("Expected a different error for confirmUsername:", errs["confirmUsername"][0])
	}

	req = mockRequest(StoreUsername, "john", "confirmUsername", "john")
	errs = Validate(req, nil, StoreUsername, "confirmUsername").Map()
	if len(errs) != 0 {
		t.Error("Expected no errors:", errs)
	}

	req = mockRequest(StoreUsername, "john", "confirmUsername", "john")
	errs = Validate(req, nil, StoreUsername).Map()
	if len(errs) != 0 {
		t.Error("Expected no errors:", errs)
	}
}

func TestFilterValidators(t *testing.T) {
	t.Parallel()

	validators := []Validator{
		mockValidator{
			FieldName: StoreUsername, Errs: ErrorList{FieldError{StoreUsername, errors.New("must be longer than 4")}},
		},
		mockValidator{
			FieldName: StorePassword, Errs: ErrorList{FieldError{StorePassword, errors.New("must be longer than 4")}},
		},
	}

	validators = FilterValidators(validators, StoreUsername)

	if len(validators) != 1 {
		t.Error("Expected length to be 1")
	}
	if validators[0].Field() != StoreUsername {
		t.Error("Expcted validator for field username", validators[0].Field())
	}
}
