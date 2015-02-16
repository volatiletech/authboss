package confirm

import (
	"html/template"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

func setup() *Confirm {
	authboss.NewConfig()
	authboss.Cfg.Storer = mocks.NewMockStorer()
	authboss.Cfg.LayoutEmail = template.Must(template.New("").Parse(`email ^_^`))

	c := &Confirm{}
	if err := c.Initialize(); err != nil {
		panic(err)
	}
	return c
}

func TestConfirm_Initialize(t *testing.T) {
	authboss.NewConfig()
	c := &Confirm{}
	if err := c.Initialize(); err == nil {
		t.Error("Should cry about not having a storer.")
	}

	c = setup()

	if c.emailTemplates == nil {
		t.Error("Missing email templates")
	}
}
