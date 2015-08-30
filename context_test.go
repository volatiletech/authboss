package authboss

import "testing"

func TestContext_SaveUser(t *testing.T) {
	t.Parallel()

	ab := New()
	ctx := ab.NewContext()
	storer := mockStorer{}
	ab.Storer = storer
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
	t.Parallel()

	ab := New()
	ctx := ab.NewContext()

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
	ab.Storer = storer
	ab.OAuth2Storer = storer

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
	t.Parallel()

	ab := New()
	ctx := ab.NewContext()
	storer := mockStorer{
		"joe": Attributes{"email": "hello@joe.com", "password": "mysticalhash"},
	}
	ab.Storer = storer
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
