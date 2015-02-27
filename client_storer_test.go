package authboss

import (
	"net/http"
	"testing"
)

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

func TestFlashClearer(t *testing.T) {
	session := mockClientStore{FlashSuccessKey: "success", FlashErrorKey: "error"}
	Cfg.SessionStoreMaker = func(w http.ResponseWriter, r *http.Request) ClientStorer {
		return session
	}

	if msg := FlashSuccess(nil, nil); msg != "success" {
		t.Error("Unexpected flash success:", msg)
	}
	if msg, ok := session.Get(FlashSuccessKey); ok {
		t.Error("Unexpected success flash:", msg)
	}

	if msg := FlashError(nil, nil); msg != "error" {
		t.Error("Unexpected flash error:", msg)
	}
	if msg, ok := session.Get(FlashErrorKey); ok {
		t.Error("Unexpected error flash:", msg)
	}

}
