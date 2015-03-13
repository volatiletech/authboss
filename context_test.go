package authboss

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

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

	if _, err := ctx.FirstFormValueErr("query"); err != nil {
		t.Error(err)
	}

	if _, err := ctx.FirstPostFormValueErr("post"); err != nil {
		t.Error(err)
	}

	if query, ok := ctx.FormValue("query1"); ok {
		t.Error("Expected query1 not to be found:", query)
	}

	if post, ok := ctx.PostFormValue("post1"); ok {
		t.Error("Expected post1 not to be found:", post)
	}

	if query, ok := ctx.FirstFormValue("query1"); ok {
		t.Error("Expected query1 not to be found:", query)
	}

	if post, ok := ctx.FirstPostFormValue("post1"); ok {
		t.Error("Expected post1 not to be found:", post)
	}

	if query, err := ctx.FirstFormValueErr("query1"); err == nil {
		t.Error("Expected query1 not to be found:", query)
	}

	if post, err := ctx.FirstPostFormValueErr("post1"); err == nil {
		t.Error("Expected post1 not to be found:", post)
	}
}

func TestContext_SaveUser(t *testing.T) {
	Cfg = NewConfig()
	ctx := NewContext()
	storer := mockStorer{}
	Cfg.Storer = storer
	ctx.User = Attributes{StoreUsername: "joe", StoreEmail: "hello@joe.com", StorePassword: "mysticalhash"}

	err := ctx.SaveUser()
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	attr, ok := storer["hello@joe.com"]
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
	Cfg = NewConfig()
	ctx := NewContext()

	attr := Attributes{
		"email":    "hello@joe.com",
		"password": "mysticalhash",
		"uid":      "what",
		"provider": "google",
	}

	storer := mockStorer{
		"joe":        attr,
		"whatgoogle": attr,
	}
	Cfg.Storer = storer
	Cfg.OAuth2Storer = storer

	ctx.User = nil
	if err := ctx.LoadUser("joe"); err != nil {
		t.Error("Unexpected error:", err)
	}

	if email, err := ctx.User.StringErr("email"); err != nil {
		t.Error(err)
	} else if email != attr["email"] {
		t.Error("Email wrong:", email)
	}
	if password, err := ctx.User.StringErr("password"); err != nil {
		t.Error(err)
	} else if password != attr["password"] {
		t.Error("Password wrong:", password)
	}

	ctx.User = nil
	if err := ctx.LoadUser("what;google"); err != nil {
		t.Error("Unexpected error:", err)
	}

	if email, err := ctx.User.StringErr("email"); err != nil {
		t.Error(err)
	} else if email != attr["email"] {
		t.Error("Email wrong:", email)
	}
	if password, err := ctx.User.StringErr("password"); err != nil {
		t.Error(err)
	} else if password != attr["password"] {
		t.Error("Password wrong:", password)
	}
}

func TestContext_LoadSessionUser(t *testing.T) {
	Cfg = NewConfig()
	ctx := NewContext()
	storer := mockStorer{
		"joe": Attributes{"email": "hello@joe.com", "password": "mysticalhash"},
	}
	Cfg.Storer = storer
	ctx.SessionStorer = mockClientStore{
		SessionKey: "joe",
	}

	err := ctx.LoadSessionUser()
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

func TestContext_Attributes(t *testing.T) {
	now := time.Now().UTC()

	ctx := NewContext()
	ctx.postFormValues = map[string][]string{
		"a":        []string{"a", "1"},
		"b_int":    []string{"5", "hello"},
		"wildcard": nil,
		"c_date":   []string{now.Format(time.RFC3339)},
	}

	attr, err := ctx.Attributes()
	if err != nil {
		t.Error(err)
	}

	if got := attr["a"].(string); got != "a" {
		t.Error("a's value is wrong:", got)
	}
	if got := attr["b"].(int); got != 5 {
		t.Error("b's value is wrong:", got)
	}
	if got := attr["c"].(time.Time); got.Unix() != now.Unix() {
		t.Error("c's value is wrong:", now, got)
	}
	if _, ok := attr["wildcard"]; ok {
		t.Error("We don't need totally empty fields.")
	}
}
