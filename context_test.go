package authboss

import (
	"bytes"
	"net/http"
	"testing"
)

func TestContext_PutGet(t *testing.T) {
	ctx := NewContext()

	ctx.Put("key", "value")
	if v, has := ctx.Get("key"); !has || v.(string) != "value" {
		t.Error("Not retrieving key values correctly.")
	}
}

func TestContext_Request(t *testing.T) {
	req, err := http.NewRequest("POST", "http://localhost?query=string", bytes.NewBufferString("post=form"))
	if err != nil {
		t.Error("Unexpected Error:", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx, err := ContextFromRequest(req)
	if err != nil {
		t.Error("Unexpected Error:", err)
	}

	if query, ok := ctx.FormValue("query"); !ok || query[0] != "string" {
		t.Error("Form value not getting recorded correctly.")
	}

	if post, ok := ctx.PostFormValue("post"); !ok || post[0] != "form" {
		t.Error("Postform value not getting recorded correctly.")
	}

	if query, ok := ctx.FirstFormValue("query"); !ok || query != "string" {
		t.Error("Form value not getting recorded correctly.")
	}

	if post, ok := ctx.FirstPostFormValue("post"); !ok || post != "form" {
		t.Error("Postform value not getting recorded correctly.")
	}
}

func TestContext_SaveUser(t *testing.T) {
	ctx := NewContext()
	storer := mockStorer{}

	ctx.User = Attributes{"email": "hello@joe.com", "password": "mysticalhash"}
	err := ctx.SaveUser("joe", storer)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	attr, ok := storer["joe"]
	if !ok {
		t.Error("Could not find joe!")
	}

	for k, v := range ctx.User {
		if v != attr[k] {
			t.Error(v, "not equal to", ctx.User[k])
		}
	}
}

func TestContext_LoadUser(t *testing.T) {
	ctx := NewContext()
	storer := mockStorer{
		"joe": Attributes{"email": "hello@joe.com", "password": "mysticalhash"},
	}

	err := ctx.LoadUser("joe", storer)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	attr := storer["joe"]

	for k, v := range attr {
		if v != ctx.User[k] {
			t.Error(v, "not equal to", ctx.User[k])
		}
	}
}
