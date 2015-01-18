package recover

import (
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"io"

	"bytes"
	"crypto/md5"
	"encoding/base64"
	"log"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/views"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplRecover         = "recover.tpl"
	tplRecoverComplete = "recover-complete.tpl"
	tplInitEmail       = "recover-init.email"

	attrUsername   = "username"
	attrResetToken = "resettoken"
	attrEmail      = "email"
)

func init() {
	m := &RecoverModule{}
	authboss.RegisterModule("recover", m)
}

type RecoverPage struct {
	Username, ConfirmUsername, Error string
}

type RecoverModule struct {
	templates      *template.Template
	routes         authboss.RouteTable
	storageOptions authboss.StorageOptions
	storer         authboss.Storer
	logger         io.Writer

	fromEmail string
}

func (m *RecoverModule) Initialize(config *authboss.Config) (err error) {
	if m.templates, err = views.Get(config.ViewsPath, tplRecover, tplRecoverComplete, tplInitEmail); err != nil {
		return err
	}

	m.routes = authboss.RouteTable{
		"recover":          m.recoverHandlerFunc,
		"recover/complete": m.recoverCompleteHandlerFunc,
	}
	m.storageOptions = authboss.StorageOptions{
		attrUsername:   authboss.String,
		attrResetToken: authboss.String,
		attrEmail:      authboss.String,
	}
	m.storer = config.Storer
	m.logger = config.LogWriter
	m.fromEmail = config.RecoverFromEmail

	return nil
}

func (m *RecoverModule) Routes() authboss.RouteTable {
	return m.routes
}

func (m *RecoverModule) Storage() authboss.StorageOptions {
	return m.storageOptions
}

func (m *RecoverModule) recoverHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		m.templates.ExecuteTemplate(w, tplRecover, nil)
	case methodPOST:
		username, ok := ctx.FirstPostFormValue("username")
		if !ok {
			fmt.Fprintln(m.logger, errors.New("recover: Expected postFormValue 'username' to be in the context"))
		}

		confirmUsername, ok := ctx.FirstPostFormValue("confirmUsername")
		if !ok {
			fmt.Fprintln(m.logger, errors.New("recover: Expected postFormValue 'confirmUsername' to be in the context"))
		}

		if err := m.initiateRecover(ctx, username, confirmUsername, r.Host); err != nil {
			fmt.Fprintln(m.logger, fmt.Sprintf("recover: %s"), err.Error())
			w.WriteHeader(http.StatusBadRequest)
			m.templates.ExecuteTemplate(w, tplRecover, RecoverPage{username, confirmUsername, err.Error()})
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *RecoverModule) initiateRecover(ctx *authboss.Context, username, confirmUsername, host string) error {
	if !strings.EqualFold(username, confirmUsername) {
		return errors.New("Confirm username does not match")
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}

	if err := ctx.LoadUser(username, m.storer); err != nil {
		return err
	}

	emailInter, ok := ctx.User[attrEmail]
	if !ok {
		return errors.New("user does not have mapped email")
	}

	email, ok := emailInter.(string)
	if !ok {
		return errors.New("user does not have a valid email")
	}

	// TODO : email regex check on to and from

	sum := md5.Sum(token)
	ctx.User[attrResetToken] = base64.StdEncoding.EncodeToString(sum[:])
	log.Printf("%#v", ctx.User)

	if err := ctx.SaveUser(username, m.storer); err != nil {
		return err
	}

	emailBody := &bytes.Buffer{}
	if err := m.templates.ExecuteTemplate(emailBody, tplInitEmail, struct{ Link string }{
		fmt.Sprintf("%s/recover/complete?token=%s", host, base64.URLEncoding.EncodeToString(token)),
	}); err != nil {
		return err
	}

	if err := authboss.SendEmail(email, m.fromEmail, emailBody.Bytes()); err != nil {
		fmt.Fprintln(m.logger, err)
	}

	return nil
}

func (m *RecoverModule) recoverCompleteHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		m.templates.ExecuteTemplate(w, tplRecoverComplete, nil)
	case methodPOST:

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
