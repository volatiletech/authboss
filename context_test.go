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
}
