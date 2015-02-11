package confirm

import (
	"html/template"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

func setup() *Confirm {
	config := authboss.NewConfig()
	config.Storer = mocks.NewMockStorer()

	config.LayoutEmail = template.Must(template.New("").Parse(`email ^_^`))

	c := &Confirm{}
	if err := c.Initialize(config); err != nil {
		panic(err)
	}
	return c
}

func TestConfirm_Initialize(t *testing.T) {
	c := &Confirm{}
	if err := c.Initialize(authboss.NewConfig()); err == nil {
		t.Error("Should cry about not having a storer.")
	}

	c = setup()

	if c.config == nil {
		t.Error("Missing config")
	}

	if c.logger == nil {
		t.Error("Missing logger")
	}

	if c.storer == nil {
		t.Error("Missing storer")
	}

	if c.emailTemplates == nil {
		t.Error("Missing email templates")
	}
}
