package authboss

import (
	"bytes"
	"strings"
	"testing"
)

func TestMailer(t *testing.T) {
	NewConfig()
	mailServer := &bytes.Buffer{}

	Cfg.Mailer = LogMailer(mailServer)
	Cfg.Storer = mockStorer{}
	Init()

	err := SendMail(Email{
		To:       []string{"some@email.com", "a@a.com"},
		ToNames:  []string{"Jake", "Noname"},
		From:     "some@guy.com",
		FromName: "Joseph",
		ReplyTo:  "an@email.com",
		Subject:  "Email!",
		TextBody: "No html here",
		HTMLBody: "<html>body</html>",
	})
	if err != nil {
		t.Error(err)
	}

	if mailServer.Len() == 0 {
		t.Error("It should have logged the e-mail.")
	}

	str := mailServer.String()
	if !strings.Contains(str, "From: Joseph <some@guy.com>") {
		t.Error("From line not present.")
	}

	if !strings.Contains(str, "To: Jake <some@email.com>, Noname <a@a.com>") {
		t.Error("To line not present.")
	}

	if !strings.Contains(str, "No html here") {
		t.Error("Text body not present.")
	}

	if !strings.Contains(str, "<html>body</html>") {
		t.Error("Html body not present.")
	}
}

func TestSMTPMailer(t *testing.T) {
	var _ Mailer = SMTPMailer("server", nil)

	recovered := false
	defer func() {
		recovered = recover() != nil
	}()

	SMTPMailer("", nil)

	if !recovered {
		t.Error("Should have panicd.")
	}
}
