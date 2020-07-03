package authboss

import (
	"testing"

	"github.com/friendsofgo/errors"
)

type mockFieldError struct {
	name string
	err  error
}

func (m mockFieldError) Name() string {
	return m.name
}

func (m mockFieldError) Err() error {
	return m.err
}

func (m mockFieldError) Error() string {
	return m.err.Error()
}

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
		mockFieldError{"username", errors.New(errNotLong)},
		mockFieldError{"username", errors.New(errEmail)},
		mockFieldError{"password", errors.New(errNotLong)},
		errors.New(errAsploded),
	}

	m := errList.Map()
	if len(m) != 3 {
		t.Error("Wrong number of fields:", len(m))
	}

	usernameErrs := m["username"]
	if len(usernameErrs) != 2 {
		t.Error("Wrong number of username errors:", len(usernameErrs))
	}
	if usernameErrs[0] != errNotLong {
		t.Error("Wrong username error at 0:", usernameErrs[0])
	}
	if usernameErrs[1] != errEmail {
		t.Error("Wrong username error at 1:", usernameErrs[1])
	}

	passwordErrs := m["password"]
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

func TestErrorList_MapHelper(t *testing.T) {
	t.Parallel()

	errList := []error{
		mockFieldError{"username", errors.New("")},
		mockFieldError{"username", errors.New("")},
		mockFieldError{"password", errors.New("")},
	}

	var _ map[string][]string = ErrorMap(errList)
}
