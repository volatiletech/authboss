package authboss

import (
	"context"
	"testing"
)

type testMailer struct{ sent bool }

func (t *testMailer) Send(context.Context, Email) error {
	t.sent = true
	return nil
}

func TestEmail(t *testing.T) {
	t.Parallel()

	ab := New()

	mailer := &testMailer{}
	renderer := &mockEmailRenderer{}
	ab.Config.Core.Mailer = mailer
	ab.Config.Core.MailRenderer = renderer

	email := Email{
		To:      []string{"support@authboss.com"},
		Subject: "Send help",
	}

	ro := EmailResponseOptions{
		Data:         nil,
		HTMLTemplate: "html",
		TextTemplate: "text",
	}

	if err := ab.Email(context.Background(), email, ro); err != nil {
		t.Error(err)
	}

	if !mailer.sent {
		t.Error("the e-mail should have been sent")
	}
}
