package authboss

import "testing"

type testClientStorerErr string

func (t testClientStorerErr) Put(key, value string) {}
func (t testClientStorerErr) Get(key string) (string, bool) {
	return string(t), key == string(t)
}
func (t testClientStorerErr) Del(key string) {}

func TestClientStorerErr(t *testing.T) {
	var cs testClientStorerErr

	csw := clientStoreWrapper{&cs}
	if _, err := csw.GetErr("hello"); err == nil {
		t.Error("Expected an error")
	}

	cs = "hello"
	if str, err := csw.GetErr("hello"); err != nil {
		t.Error(err)
	} else if str != "hello" {
		t.Error("Wrong value:", str)
	}
}
