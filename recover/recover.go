package recover

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/flashutil"
	"gopkg.in/authboss.v0/internal/views"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin           = "login.tpl"
	tplRecover         = "recover.tpl"
	tplRecoverComplete = "recover-complete.tpl"
	tplInitHTMLEmail   = "recover-html.email"
	tplInitTextEmail   = "recover-text.email"

	attrUsername           = "username"
	attrRecoverToken       = "recover_token"
	attrRecoverTokenExpiry = "recover_token_expiry"
	attrEmail              = "email"
	attrPassword           = "password"

	errFormat = "recover [%s]: %s\n"
)

func init() {
	m := &RecoverModule{}
	authboss.RegisterModule("recover", m)
}

type RecoverModule struct {
	templates      views.Templates
	emailTemplates views.Templates
	config         *authboss.Config
}

func (m *RecoverModule) Initialize(config *authboss.Config) (err error) {
	if config.Storer == nil {
		return errors.New("recover: Need a RecoverStorer.")
	}

	if _, ok := config.Storer.(authboss.RecoverStorer); !ok {
		return errors.New("recover: RecoverStorer required for recover functionality.")
	}

	if m.templates, err = views.Get(config.Layout, config.ViewsPath, tplRecover, tplRecoverComplete); err != nil {
		return err
	}

	if m.emailTemplates, err = views.Get(config.LayoutEmail, config.ViewsPath, tplInitHTMLEmail, tplInitTextEmail); err != nil {
		return err
	}

	m.config = config

	return nil
}

func (m *RecoverModule) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"recover":          m.recoverHandlerFunc,
		"recover/complete": m.recoverCompleteHandlerFunc,
	}
}
func (m *RecoverModule) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		attrUsername:           authboss.String,
		attrRecoverToken:       authboss.String,
		attrEmail:              authboss.String,
		attrRecoverTokenExpiry: authboss.String,
		attrPassword:           authboss.String,
	}
}

type pageRecover struct {
	Username, ConfirmUsername string
	ErrMap                    map[string][]string
	FlashSuccess              string
	FlashError                string
}

func (m *RecoverModule) recoverHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	execTpl := func(data interface{}) {
		if err := m.templates.ExecuteTemplate(w, tplRecover, data); err != nil {
			fmt.Fprintf(m.config.LogWriter, errFormat, "unable to execute template", err)
		}
	}

	switch r.Method {
	case methodGET:
		execTpl(pageRecover{FlashError: flashutil.Pull(ctx.SessionStorer, authboss.FlashErrorKey)})
	case methodPOST:
		// ignore ok checks as we validate these fields anyways
		username, _ := ctx.FirstPostFormValue("username")
		confirmUsername, _ := ctx.FirstPostFormValue("confirmUsername")

		policies := authboss.FilterValidators(m.config.Policies, "username")
		if validationErrs := ctx.Validate(policies, m.config.ConfirmFields...); len(validationErrs) > 0 {
			fmt.Fprintf(m.config.LogWriter, errFormat, "validation failed", validationErrs)
			execTpl(pageRecover{username, confirmUsername, validationErrs.Map(), "", ""})
			return
		}

		if err := m.recover(ctx, username); err != nil {
			// never reveal failed usernames to prevent sniffing
			fmt.Fprintf(m.config.LogWriter, errFormat, "failed to recover", err)
			execTpl(pageRecover{username, confirmUsername, nil, "", m.config.RecoverFailedErrorFlash})
			return
		}

		ctx.SessionStorer.Put(authboss.FlashSuccessKey, m.config.RecoverInitiateSuccessFlash)
		http.Redirect(w, r, m.config.RecoverRedirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *RecoverModule) recover(ctx *authboss.Context, username string) (err error) {
	if err := ctx.LoadUser(username, m.config.Storer); err != nil {
		return err
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	sum := md5.Sum(token)

	ctx.User[attrRecoverToken] = base64.StdEncoding.EncodeToString(sum[:])
	ctx.User[attrRecoverTokenExpiry] = time.Now().Add(m.config.RecoverTokenDuration)

	if err := ctx.SaveUser(username, m.config.Storer); err != nil {
		return err
	}

	if email, ok := ctx.User.String(attrEmail); !ok {
		return errors.New("email not found; unable to send email")
	} else {
		go m.sendRecoverEmail(email, token)
	}

	return nil
}

func (m *RecoverModule) sendRecoverEmail(to string, token []byte) {
	data := struct{ Link string }{fmt.Sprintf("%s/recover/complete?token=%s", m.config.HostName, base64.URLEncoding.EncodeToString(token))}

	htmlEmailBody := &bytes.Buffer{}
	if err := m.emailTemplates.ExecuteTemplate(htmlEmailBody, tplInitHTMLEmail, data); err != nil {
		fmt.Fprintf(m.config.LogWriter, errFormat, "failed to build html tpl", err)
	}

	textEmaiLBody := &bytes.Buffer{}
	if err := m.emailTemplates.ExecuteTemplate(textEmaiLBody, tplInitTextEmail, data); err != nil {
		fmt.Fprintf(m.config.LogWriter, errFormat, "failed to build plaintext tpl", err)
	}

	if err := m.config.Mailer.Send(authboss.Email{
		To:       []string{to},
		ToNames:  []string{""},
		From:     m.config.EmailFrom,
		Subject:  "Password Reset",
		TextBody: textEmaiLBody.String(),
		HTMLBody: htmlEmailBody.String(),
	}); err != nil {
		fmt.Fprintf(m.config.LogWriter, errFormat, "failed to send email", err)
	}
}

type pageRecoverComplete struct {
	Token        string
	ErrMap       map[string][]string
	FlashSuccess string
	FlashError   string
}

func (m *RecoverModule) recoverCompleteHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	execTpl := func(name string, data interface{}) {
		if err := m.templates.ExecuteTemplate(w, name, data); err != nil {
			fmt.Fprintf(m.config.LogWriter, errFormat, "unable to execute template", err)
		}
	}

	switch r.Method {
	case methodGET:
		token, ok := ctx.FirstFormValue("token")
		if !ok {
			fmt.Fprintln(m.config.LogWriter, "recover: expected form value token")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		var err error
		ctx.User, err = m.verifyToken(token)
		if err != nil {
			fmt.Fprintln(m.config.LogWriter, "recover:", err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		expiry, ok := ctx.User.DateTime(attrRecoverTokenExpiry)
		if !ok || time.Now().After(expiry) {
			fmt.Fprintln(m.config.LogWriter, "recover: token has expired:", expiry)
			ctx.SessionStorer.Put(authboss.FlashErrorKey, m.config.RecoverTokenExpiredFlash)
			http.Redirect(w, r, "/recover", http.StatusFound)
			return
		}

		execTpl(tplRecoverComplete, pageRecoverComplete{
			FlashError: flashutil.Pull(ctx.SessionStorer, authboss.FlashErrorKey),
			Token:      token,
		})
	case methodPOST:
		token, ok := ctx.FirstFormValue("token")
		if !ok {
			fmt.Fprintln(m.config.LogWriter, "recover: expected form value token")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		var err error
		ctx.User, err = m.verifyToken(token)
		if err != nil {
			fmt.Fprintln(m.config.LogWriter, "recover 1234:", err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		policies := authboss.FilterValidators(m.config.Policies, "password")
		if validationErrs := ctx.Validate(policies, m.config.ConfirmFields...); len(validationErrs) > 0 {
			execTpl(tplRecoverComplete, pageRecoverComplete{Token: token, ErrMap: validationErrs.Map()})
			return
		}

		password, _ := ctx.FirstFormValue("password")
		encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), m.config.BCryptCost)
		if err != nil {
			fmt.Fprintln(m.config.LogWriter, "recover: failed to encrypt password")
			execTpl(tplRecoverComplete, pageRecoverComplete{Token: token, FlashError: m.config.RecoverFailedErrorFlash})
			return
		}
		ctx.User[attrPassword] = string(encryptedPassword)

		username, ok := ctx.User.String(attrUsername)
		if !ok {
			fmt.Println(m.config.LogWriter, "reover: expected user attribue missing:", attrUsername)
			execTpl(tplRecoverComplete, pageRecoverComplete{Token: token, FlashError: m.config.RecoverFailedErrorFlash})
			return
		}
		ctx.User[attrRecoverToken] = ""
		ctx.User[attrRecoverTokenExpiry] = time.Now().UTC()

		if err := ctx.SaveUser(username, m.config.Storer); err != nil {
			fmt.Fprintln(m.config.LogWriter, "recover asdf:", err)
			execTpl(tplRecoverComplete, pageRecoverComplete{Token: token, FlashError: m.config.RecoverFailedErrorFlash})
			return
		}

		ctx.SessionStorer.Put(authboss.SessionKey, username)
		http.Redirect(w, r, m.config.AuthLoginSuccessRoute, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *RecoverModule) verifyToken(token string) (attrs authboss.Attributes, err error) {
	decodedToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	sum := md5.Sum(decodedToken)
	userInter, err := m.config.Storer.(authboss.RecoverStorer).RecoverUser(base64.StdEncoding.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}

	return authboss.Unbind(userInter), nil
}
