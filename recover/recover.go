package recover

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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

	if config.Layout == nil {
		return errors.New("recover: Layout required for Recover functionallity.")
	}
	if m.templates, err = views.Get(config.Layout, config.ViewsPath, tplRecover, tplRecoverComplete); err != nil {
		return err
	}

	if config.LayoutEmail == nil {
		return errors.New("recover: LayoutEmail required for Recover functionallity.")
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

func (m *RecoverModule) execTpl(tpl string, w http.ResponseWriter, data interface{}) {
	buffer, err := m.templates.ExecuteTemplate(tpl, data)
	if err != nil {
		fmt.Fprintf(m.config.LogWriter, errFormat, "unable to execute template", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := io.Copy(w, buffer); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

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

var errRecoveryTokenExpired = errors.New("recovery token expired")

type pageRecoverComplete struct {
	Token, Password, ConfirmPassword string
	ErrMap                           map[string][]string
	FlashSuccess, FlashError         string
}

func (m *RecoverModule) recoverCompleteHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		_, err := verifyToken(ctx, m.config.Storer.(authboss.RecoverStorer))
		if err != nil {
			if err.Error() == errRecoveryTokenExpired.Error() {
				fmt.Fprintln(m.config.LogWriter, "recover [token expired]:", err)
				ctx.SessionStorer.Put(authboss.FlashErrorKey, m.config.RecoverTokenExpiredFlash)
				http.Redirect(w, r, "/recover", http.StatusFound)
				return
			} else {
				fmt.Fprintln(m.config.LogWriter, "recover:", err)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}

		token, _ := ctx.FirstFormValue("token")

		page := pageRecoverComplete{
			Token:      token,
			FlashError: flashutil.Pull(ctx.SessionStorer, authboss.FlashErrorKey),
		}
		m.execTpl(tplRecoverComplete, w, page)
	case methodPOST:
		errPage := m.recoverComplete(ctx)
		if errPage != nil {
			m.execTpl(tplRecoverComplete, w, *errPage)
			return
		}

		http.Redirect(w, r, m.config.AuthLoginSuccessRoute, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// verifyToken expects a base64.URLEncoded token.
func verifyToken(ctx *authboss.Context, storer authboss.RecoverStorer) (attrs authboss.Attributes, err error) {
	token, ok := ctx.FirstFormValue("token")
	if !ok {
		return nil, errors.New("missing form value: token")
	}

	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	sum := md5.Sum(decoded)
	userInter, err := storer.RecoverUser(base64.StdEncoding.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}

	attrs = authboss.Unbind(userInter)

	expiry, ok := attrs.DateTime(attrRecoverTokenExpiry)
	if !ok || time.Now().After(expiry) {
		return nil, errRecoveryTokenExpired
	}

	return attrs, nil
}

func (m *RecoverModule) recoverComplete(ctx *authboss.Context) (errPage *pageRecoverComplete) {
	token, _ := ctx.FirstFormValue("token")
	password, _ := ctx.FirstPostFormValue("password")
	confirmPassword, _ := ctx.FirstPostFormValue("confirmPassword")
	defaultErrPage := &pageRecoverComplete{token, password, confirmPassword, nil, "", m.config.RecoverFailedErrorFlash}

	var err error
	ctx.User, err = verifyToken(ctx, m.config.Storer.(authboss.RecoverStorer))
	if err != nil {
		fmt.Fprintf(m.config.LogWriter, errFormat, "failed to verify token", err)
		return defaultErrPage
	}

	policies := authboss.FilterValidators(m.config.Policies, "password")
	if validationErrs := ctx.Validate(policies, m.config.ConfirmFields...); len(validationErrs) > 0 {
		fmt.Fprintf(m.config.LogWriter, errFormat, "validation failed", validationErrs)
		return &pageRecoverComplete{token, password, confirmPassword, validationErrs.Map(), "", ""}
	}

	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), m.config.BCryptCost)
	if err != nil {
		fmt.Fprintf(m.config.LogWriter, errFormat, "failed to encrypt password", err)
		return defaultErrPage
	}
	ctx.User[attrPassword] = string(encryptedPassword)
	ctx.User[attrRecoverToken] = ""
	var nullTime time.Time
	ctx.User[attrRecoverTokenExpiry] = nullTime

	username, _ := ctx.User.String(attrUsername)
	if err := ctx.SaveUser(username, m.config.Storer); err != nil {
		fmt.Fprintf(m.config.LogWriter, errFormat, "failed to save user", err)
		return defaultErrPage
	}

	ctx.SessionStorer.Put(authboss.SessionKey, username)
	return nil
}
