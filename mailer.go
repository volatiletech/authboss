package authboss

import (
	"fmt"
	"io"
)

var (
	emailer mailer
)

type Mailer int

const (
	MailerLog Mailer = iota
	MailerSMTP
)

func SendEmail(to, from string, msg []byte) (err error) {
	return emailer.Send(to, from, msg)
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
	fmt.Fprintf(e.writer, "[emailer] Sent Email => to [%s], from [%s], msg [%s]", to, from, msg)
	return nil
}
