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
	FlashSuccess, FlashError  string
	XSRFName, XSRFToken       string
}

func (m *RecoverModule) recoverHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		page := pageRecover{
			FlashError: flashutil.Pull(ctx.SessionStorer, authboss.FlashErrorKey),
			XSRFName:   authboss.Cfg.XSRFName,
			XSRFToken:  authboss.Cfg.XSRFMaker(w, r),
		}

		m.execTpl(tplRecover, w, page)
	case methodPOST:
		errPage, _ := m.recover(ctx, authboss.Cfg.XSRFName, authboss.Cfg.XSRFMaker(w, r))

		if errPage != nil {
			m.execTpl(tplRecover, w, *errPage)
			return
		}

		ctx.SessionStorer.Put(authboss.FlashSuccessKey, authboss.Cfg.RecoverInitiateSuccessFlash)
		http.Redirect(w, r, authboss.Cfg.RecoverRedirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *RecoverModule) recover(ctx *authboss.Context, xsrfName, xsrfToken string) (errPage *pageRecover, emailSent <-chan struct{}) {
	username, _ := ctx.FirstPostFormValue("username")
	confirmUsername, _ := ctx.FirstPostFormValue("confirmUsername")

	policies := authboss.FilterValidators(authboss.Cfg.Policies, "username")
	if validationErrs := ctx.Validate(policies, authboss.Cfg.ConfirmFields...); len(validationErrs) > 0 {
		fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "validation failed", validationErrs)
		return &pageRecover{
			Username:        username,
			ConfirmUsername: confirmUsername,
			ErrMap:          validationErrs.Map(),
			XSRFName:        xsrfName,
			XSRFToken:       xsrfToken,
		}, nil
	}

	err, emailSent := m.makeAndSendToken(ctx, username)
	if err != nil {
		fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "failed to recover", err)
		return &pageRecover{
			Username:        username,
			ConfirmUsername: confirmUsername,
			FlashError:      authboss.Cfg.RecoverFailedErrorFlash,
			XSRFName:        xsrfName,
			XSRFToken:       xsrfToken,
		}, nil
	}

	return nil, emailSent
}

func (m *RecoverModule) makeAndSendToken(ctx *authboss.Context, username string) (err error, emailSent <-chan struct{}) {
	if err = ctx.LoadUser(username); err != nil {
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
	ctx.User[attrRecoverTokenExpiry] = time.Now().Add(authboss.Cfg.RecoverTokenDuration)

	if err = ctx.SaveUser(username, authboss.Cfg.Storer); err != nil {
		return err, nil
	}

	return nil, m.sendRecoverEmail(email, token)
}

func (m *RecoverModule) sendRecoverEmail(to string, token []byte) <-chan struct{} {
	emailSent := make(chan struct{}, 1)

	go func() {
		data := struct{ Link string }{fmt.Sprintf("%s/recover/complete?token=%s", authboss.Cfg.HostName, base64.URLEncoding.EncodeToString(token))}

		htmlEmailBody, err := m.emailTemplates.ExecuteTemplate(tplInitHTMLEmail, data)
		if err != nil {
			fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "failed to build html email", err)
			close(emailSent)
			return
		}

		textEmaiLBody, err := m.emailTemplates.ExecuteTemplate(tplInitTextEmail, data)
		if err != nil {
			fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "failed to build plaintext email", err)
			close(emailSent)
			return
		}

		if err := authboss.Cfg.Mailer.Send(authboss.Email{
			To:       []string{to},
			ToNames:  []string{""},
			From:     authboss.Cfg.EmailFrom,
			Subject:  authboss.Cfg.EmailSubjectPrefix + "Password Reset",
			TextBody: textEmaiLBody.String(),
			HTMLBody: htmlEmailBody.String(),
		}); err != nil {
			fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "failed to send email", err)
			close(emailSent)
			return
		}

		emailSent <- struct{}{}
	}()

	return emailSent
}
