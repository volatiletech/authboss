package authboss

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/smtp"
	"strings"
	"text/template"
	"time"
)

// SendMail uses the currently configured mailer to deliver e-mails.
func (a *Authboss) SendMail(ctx context.Context, data Email) error {
	return a.Mailer.Send(ctx, data)
}

// Mailer is a type that is capable of sending an e-mail.
type Mailer interface {
	Send(context.Context, Email) error
}

// LogMailer creates a mailer that doesn't deliver e-mails but
// simply logs them.
func LogMailer(writer io.Writer) Mailer {
	return logMailer{writer}
}

// SMTPMailer creates an SMTP Mailer to send emails with.
func SMTPMailer(server string, auth smtp.Auth) Mailer {
	if len(server) == 0 {
		panic("SMTP Mailer must be created with a server string.")
	}
	random := rand.New(rand.NewSource(time.Now()))
	return smtpMailer{server, auth, random}
}

// Email all the things. The ToNames and friends are parallel arrays and must
// be 0-length or the same length as their counterpart. To omit a name
// for a user at an index in To simply use an empty string at that
// index in ToNames.
type Email struct {
	To, Cc, Bcc                []string
	ToNames, CcNames, BccNames []string
	FromName, From             string
	ReplyToName, ReplyTo       string
	Subject                    string

	TextBody string
	HTMLBody string
}

type logMailer struct {
	io.Writer
}

func (l logMailer) Send(mail Email) error {
	buf := &bytes.Buffer{}

	data := struct {
		Boundary string
		Mail     Email
	}{
		Boundary: "284fad24nao8f4na284f2n4",
		Mail:     mail,
	}

	err := emailTmpl.Execute(buf, data)
	if err != nil {
		return err
	}

	toSend := bytes.Replace(buf.Bytes(), []byte{'\n'}, []byte{'\r', '\n'}, -1)

	_, err = l.Write(toSend)
	return err
}

type smtpMailer struct {
	Server string
	Auth   smtp.Auth
	rand   *rand.Rand
}

func (s smtpMailer) Send(mail Email) error {
	buf := &bytes.Buffer{}

	data := struct {
		Boundary string
		Mail     Email
	}{
		Boundary: boundary(),
		Mail:     mail,
	}

	err := emailTmpl.Execute(buf, data)
	if err != nil {
		return err
	}

	toSend := bytes.Replace(buf.Bytes(), []byte{'\n'}, []byte{'\r', '\n'}, -1)

	return smtp.SendMail(s.Server, s.Auth, data.From, data.To, toSend)
}

// boundary makes mime boundaries, these are largely useless strings that just
// need to be the same in the mime structure. We choose from the alphabet below
// and create a random string of length 23
// Example:
// 284fad24nao8f4na284f2n4
func (s smtpMailer) boundary() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := &bytes.Buffer{}

	for i := 0; i < 23; i++ {
		buf.WriteByte(alphabet[s.rand.Int()%len(alphabet)])
	}

	return buf.String()
}

func namedAddress(name, address string) string {
	if len(name) == 0 {
		return address
	}

	return fmt.Sprintf("%s <%s>", name, address)
}

func namedAddresses(names, addresses []string) string {
	if len(names) == 0 {
		return strings.Join(addresses, ", ")
	}

	buf := &bytes.Buffer{}
	first := true

	for i, address := range addresses {
		if first {
			first = false
		} else {
			buf.WriteString(", ")
		}

		buf.WriteString(namedAddress(names[i], address))
	}

	return buf.String()
}

var emailTmpl = template.Must(template.New("email").Funcs(template.FuncMap{
	"join":           strings.Join,
	"namedAddress":   namedAddress,
	"namedAddresses": namedAddresses,
}).Parse(`To: {{namedAddresses .Mail.ToNames .Mail.To}}{{if .Mail.Cc}}
Cc: {{namedAddresses .Mail.CcNames .Mail.Cc}}{{end}}{{if .Mail.Bcc}}
Bcc: {{namedAddresses .Mail.BccNames .Mail.Bcc}}{{end}}
From: {{namedAddress .Mail.FromName .Mail.From}}
Subject: {{.Mail.Subject}}{{if .Mail.ReplyTo}}
Reply-To: {{namedAddress .Mail.ReplyToName .Mail.ReplyTo}}{{end}}
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="==============={{.Boundary}}=="
Content-Transfer-Encoding: 7bit

--==============={{.Boundary}}==
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

{{.Mail.TextBody}}
--==============={{.Boundary}}==
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

{{.Mail.HTMLBody}}
--==============={{.Boundary}}==--
`))
