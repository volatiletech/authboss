package authboss

import (
	"context"
)

// SendMail uses the currently configured mailer to deliver e-mails.
func (a *Authboss) SendMail(ctx context.Context, data Email) error {
	return a.Mailer.Send(ctx, data)
}

// Mailer is a type that is capable of sending an e-mail.
type Mailer interface {
	Send(context.Context, Email) error
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
