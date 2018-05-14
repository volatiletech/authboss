package authboss

import "testing"

type testAssertionValues struct{}

func (testAssertionValues) Validate() []error            { return nil }
func (testAssertionValues) GetPID() string               { return "" }
func (testAssertionValues) GetPassword() string          { return "" }
func (testAssertionValues) GetToken() string             { return "" }
func (testAssertionValues) GetShouldRemember() bool      { return false }
func (testAssertionValues) GetValues() map[string]string { return nil }

type testAssertionFailValues struct{}

func (testAssertionFailValues) Validate() []error { return nil }

func TestValueAssertions(t *testing.T) {
	t.Parallel()

	v := testAssertionValues{}
	fv := testAssertionFailValues{}

	paniced := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				paniced = true
			}

		}()

		MustHaveUserValues(v)
		MustHaveConfirmValues(v)
		MustHaveRecoverStartValues(v)
		MustHaveRecoverMiddleValues(v)
		MustHaveRecoverEndValues(v)
	}()

	if paniced {
		t.Error("The mock storer should have included all interfaces and should not panic")
	}

	didPanic := func(f func()) (paniced bool) {
		defer func() {
			if r := recover(); r != nil {
				paniced = true
			}
		}()

		f()
		return paniced
	}

	if !didPanic(func() { MustHaveUserValues(fv) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { MustHaveConfirmValues(fv) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { MustHaveRecoverStartValues(fv) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { MustHaveRecoverMiddleValues(fv) }) {
		t.Error("should have panic'd")
	}
	if !didPanic(func() { MustHaveRecoverEndValues(fv) }) {
		t.Error("should have panic'd")
	}
}
