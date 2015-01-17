package authboss

import (
	"fmt"
	"io"
)

type Mailer int

const (
	MailerLog Mailer = iota
	MailerSMTP
)

func SendEmail(to, from string, msg []byte) {

}

type mailer interface {
	Send(to, from string, msg []byte) error
}

type logMailer struct {
	writer io.Writer
}

func newLogMailer(w io.Writer) logMailer {
	return logMailer{w}
}

func (e logMailer) Send(to, from string, msg []byte) error {
	fmt.Fprintf(e.writer, "email sent\n\nto:\t %s\nfrom:\t %s\nmsg: %s", to, from, msg)
	return nil
}
