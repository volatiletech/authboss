package authboss

import (
	"errors"
	"testing"
)

func TestErrorList_Error(t *testing.T) {
	errList := ErrorList{errors.New("one"), errors.New("two")}
	if e := errList.Error(); e != "one, two" {
		t.Error("Wrong value for error:", e)
	}
}
