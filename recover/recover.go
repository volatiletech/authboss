package recover

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"io"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/views"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin           = "login.tpl"
	tplRecover         = "recover.tpl"
	tplRecoverComplete = "recover-complete.tpl"
	tplInitEmail       = "recover-init.email"

	attrUsername     = "username"
	attrRecoverToken = "recover_token"
	attrEmail        = "email"
)

func init() {
	m := &RecoverModule{}
	authboss.RegisterModule("recover", m)
}

type RecoverPage struct {
	Username, ConfirmUsername string
	ErrMap                    map[string][]string
}

type RecoverModule struct {
	templates                   *template.Template
	routes                      authboss.RouteTable
	storageOptions              authboss.StorageOptions
	storer                      authboss.RecoverStorer
	logger                      io.Writer
	policies                    []authboss.Validator
	confirmFields               []string
	hostName                    string
	recoverInitiateRedirect     string
	recoverInitiateSuccessFlash string
	fromEmail                   string
}

func (m *RecoverModule) Initialize(config *authboss.Config) (err error) {
	if config.Storer == nil {
		return errors.New("recover: Need a RecoverStorer.")
	}

	if storer, ok := config.Storer.(authboss.RecoverStorer); !ok {
		return errors.New("recover: RecoverStorer required for recover functionality.")
	} else {
		m.storer = storer
	}

	if m.templates, err = views.Get(config.ViewsPath, tplRecover, tplRecoverComplete, tplInitEmail); err != nil {
		return err
	}

	m.routes = authboss.RouteTable{
		"recover": m.recoverHandlerFunc,
		//"recover/complete": m.recoverCompleteHandlerFunc,
	}
	m.storageOptions = authboss.StorageOptions{
		attrUsername:     authboss.String,
		attrRecoverToken: authboss.String,
		attrEmail:        authboss.String,
	}
	m.logger = config.LogWriter
	m.fromEmail = config.RecoverFromEmail
	m.hostName = config.HostName
	m.recoverInitiateRedirect = config.RecoverInitiateRedirect
	m.recoverInitiateSuccessFlash = config.RecoverInitiateSuccessFlash
	m.policies = config.Policies
	m.confirmFields = config.ConfirmFields

	return nil
}

func (m *RecoverModule) Routes() authboss.RouteTable      { return m.routes }
func (m *RecoverModule) Storage() authboss.StorageOptions { return m.storageOptions }

func (m *RecoverModule) recoverHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		m.templates.ExecuteTemplate(w, tplRecover, nil)
	case methodPOST:
		username, _ := ctx.FirstPostFormValue("username")
		confirmUsername, _ := ctx.FirstPostFormValue("confirmUsername")

		policies := authboss.FilterValidators(m.policies, "username")
		if validationErrs := ctx.Validate(policies, m.confirmFields...); len(validationErrs) > 0 {
			err := m.templates.ExecuteTemplate(w, tplRecover, RecoverPage{username, confirmUsername, validationErrs.Map()})
			if err != nil {
				fmt.Fprintln(m.logger, "recover:", err)
			}
			return
		}

		if err := m.initiateRecover(ctx, username, confirmUsername); err != nil {
			fmt.Fprintln(m.logger, fmt.Sprintf("recover: %s", err.Error()))
		}

		ctx.SessionStorer.Put(authboss.FlashSuccessKey, m.recoverInitiateSuccessFlash)
		http.Redirect(w, r, m.recoverInitiateRedirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *RecoverModule) initiateRecover(ctx *authboss.Context, username, confirmUsername string) (err error) {
	if err := ctx.LoadUser(username, m.storer); err != nil {
		return err
	}

	email, ok := ctx.User.String(attrEmail)
	if !ok {
		return fmt.Errorf("missing attr: %s", email)
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}

	sum := md5.Sum(token)
	ctx.User[attrRecoverToken] = base64.StdEncoding.EncodeToString(sum[:])

	if err := ctx.SaveUser(username, m.storer); err != nil {
		return err
	}

	emailBody := &bytes.Buffer{}
	if err := m.templates.ExecuteTemplate(emailBody, tplInitEmail, struct{ Link string }{
		fmt.Sprintf("%s/recover/complete?token=%s", m.hostName, base64.URLEncoding.EncodeToString(sum[:])),
	}); err != nil {
		return err
	}

	return authboss.SendEmail(email, m.fromEmail, emailBody.Bytes())
}

/*func (m *RecoverModule) recoverCompleteHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:

		token, ok := ctx.FirstFormValue("token")
		if !ok {
			fmt.Fprintln(m.logger, "recover: expected value token")
			//http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		userAttrs, err := m.verifyToken(token);
		if err != nil {
			fmt.Fprintf(m.logger, "recover: %s", err)
			//http.Redirect(w, r, urlStr, code)
			return
		}



		m.templates.ExecuteTemplate(w, tplRecoverComplete, nil)
	case methodPOST:
		//if err := completeRecover(ctx); err :=
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *RecoverModule) verifyToken(token) (attrs authboss.Attributes, err) {
	decodedToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	sum := md5.Sum(decodedToken)

	userInter, err := m.storer.RecoverUser(base64.StdEncoding.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}

	return authboss.Unbind(userInter), nil
}

func (m *RecoverModule) completeRecover(ctx *authboss.Context, password, confirmPassword string) error {
	if password == confirmPassword {
		return errors.New("Passwords do not match")
	}

	return nil
}
*/
