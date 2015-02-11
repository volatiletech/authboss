package recover

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/flashutil"
)

type pageRecover struct {
	Username, ConfirmUsername string
	ErrMap                    map[string][]string
	FlashSuccess              string
	FlashError                string
}

func (m *RecoverModule) recoverHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		page := pageRecover{
			FlashError: flashutil.Pull(ctx.SessionStorer, authboss.FlashErrorKey),
		}

		m.execTpl(tplRecover, w, page)
	case methodPOST:
		errPage, _ := m.recover(ctx)

		if errPage != nil {
			m.execTpl(tplRecover, w, *errPage)
			return
		}

		ctx.SessionStorer.Put(authboss.FlashSuccessKey, m.config.RecoverInitiateSuccessFlash)
		http.Redirect(w, r, m.config.RecoverRedirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *RecoverModule) recover(ctx *authboss.Context) (errPage *pageRecover, emailSent <-chan struct{}) {
	username, _ := ctx.FirstPostFormValue("username")
	confirmUsername, _ := ctx.FirstPostFormValue("confirmUsername")

	policies := authboss.FilterValidators(m.config.Policies, "username")
	if validationErrs := ctx.Validate(policies, m.config.ConfirmFields...); len(validationErrs) > 0 {
		fmt.Fprintf(m.config.LogWriter, errFormat, "validation failed", validationErrs)
		return &pageRecover{username, confirmUsername, validationErrs.Map(), "", ""}, nil
	}

	err, emailSent := m.makeAndSendToken(ctx, username)
	if err != nil {
		fmt.Fprintf(m.config.LogWriter, errFormat, "failed to recover", err)
		return &pageRecover{username, confirmUsername, nil, "", m.config.RecoverFailedErrorFlash}, nil
	}

	return nil, emailSent
}

func (m *RecoverModule) makeAndSendToken(ctx *authboss.Context, username string) (err error, emailSent <-chan struct{}) {
	if err = ctx.LoadUser(username, m.config.Storer); err != nil {
		return err, nil
	}

	email, ok := ctx.User.String(attrEmail)
	if !ok || email == "" {
		return fmt.Errorf("email required: %v", attrEmail), nil
	}

	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return err, nil
	}
	sum := md5.Sum(token)

	ctx.User[attrRecoverToken] = base64.StdEncoding.EncodeToString(sum[:])
	ctx.User[attrRecoverTokenExpiry] = time.Now().Add(m.config.RecoverTokenDuration)

	if err = ctx.SaveUser(username, m.config.Storer); err != nil {
		return err, nil
	}

	return nil, m.sendRecoverEmail(email, token)
}

func (m *RecoverModule) sendRecoverEmail(to string, token []byte) <-chan struct{} {
	emailSent := make(chan struct{}, 1)

	go func() {
		data := struct{ Link string }{fmt.Sprintf("%s/recover/complete?token=%s", m.config.HostName, base64.URLEncoding.EncodeToString(token))}

		htmlEmailBody, err := m.emailTemplates.ExecuteTemplate(tplInitHTMLEmail, data)
		if err != nil {
			fmt.Fprintf(m.config.LogWriter, errFormat, "failed to build html email", err)
			close(emailSent)
			return
		}

		textEmaiLBody, err := m.emailTemplates.ExecuteTemplate(tplInitTextEmail, data)
		if err != nil {
			fmt.Fprintf(m.config.LogWriter, errFormat, "failed to build plaintext email", err)
			close(emailSent)
			return
		}

		if err := m.config.Mailer.Send(authboss.Email{
			To:       []string{to},
			ToNames:  []string{""},
			From:     m.config.EmailFrom,
			Subject:  m.config.EmailSubjectPrefix + "Password Reset",
			TextBody: textEmaiLBody.String(),
			HTMLBody: htmlEmailBody.String(),
		}); err != nil {
			fmt.Fprintf(m.config.LogWriter, errFormat, "failed to send email", err)
			close(emailSent)
			return
		}

		emailSent <- struct{}{}
	}()

	return emailSent
}
