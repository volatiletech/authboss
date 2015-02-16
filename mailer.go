package authboss

import (
	"bytes"
	"fmt"
	"io"
	"net/smtp"
	"strings"
	"text/template"
)

// SendMail uses the currently configured mailer to deliver e-mails.
func SendMail(data Email) error {
	return Cfg.Mailer.Send(data)
}

// Mailer is a type that is capable of sending an e-mail.
type Mailer interface {
	Send(Email) error
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
	return smtpMailer{server, auth}
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

func (l logMailer) Send(data Email) error {
	buf := &bytes.Buffer{}
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
}

func (s smtpMailer) Send(data Email) error {
	buf := &bytes.Buffer{}
	err := emailTmpl.Execute(buf, data)
	if err != nil {
		return err
	}

	toSend := bytes.Replace(buf.Bytes(), []byte{'\n'}, []byte{'\r', '\n'}, -1)

	return smtp.SendMail(s.Server, s.Auth, data.From, data.To, toSend)
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
}).Parse(`To: {{namedAddresses .ToNames .To}}{{if .Cc}}
Cc: {{namedAddresses .CcNames .Cc}}{{end}}{{if .Bcc}}
Bcc: {{namedAddresses .BccNames .Bcc}}{{end}}
From: {{namedAddress .FromName .From}}
Subject: {{.Subject}}{{if .ReplyTo}}
Reply-To: {{namedAddress .ReplyToName .ReplyTo}}{{end}}
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="===============284fad24nao8f4na284f2n4=="
Content-Transfer-Encoding: 7bit

--===============284fad24nao8f4na284f2n4==
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

{{.TextBody}}
--===============284fad24nao8f4na284f2n4==
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

{{.HTMLBody}}
--===============284fad24nao8f4na284f2n4==--
`))
