package recover

import (
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"

	"io"

	"gopkg.in/authboss.v0"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	pageRecover = "recover.tpl"

	attrUsername   = "username"
	attrResetToken = "resettoken"
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
}

func (m *RecoverModule) Initialize(c *authboss.Config) (err error) {
	if m.templates, err = template.ParseFiles(filepath.Join(c.ViewsPath, pageRecover)); err != nil {
		var recoverTplBytes []byte
		if recoverTplBytes, err = views_recover_tpl_bytes(); err != nil {
			return err
		}

		if m.templates, err = template.New(pageRecover).Parse(string(recoverTplBytes)); err != nil {
			return err
		}
	}

	m.routes = authboss.RouteTable{
		"recover": m.recoverHandlerFunc,
	}
	m.storageOptions = authboss.StorageOptions{
		attrUsername:   authboss.String,
		attrResetToken: authboss.String,
	}
	m.storer = c.Storer
	m.logger = c.LogWriter

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
		m.templates.ExecuteTemplate(w, pageRecover, nil)
	case methodPOST:
		username, ok := ctx.FirstPostFormValue("username")
		if !ok {
			fmt.Fprintln(m.logger, errors.New("recover: Expected postFormValue 'username' to be in the context"))
		}

		confirmUsername, ok := ctx.FirstPostFormValue("confirmUsername")
		if !ok {
			fmt.Fprintln(m.logger, errors.New("recover: Expected postFormValue 'confirmUsername' to be in the context"))
		}

		if err := m.initiateRecover(ctx, username, confirmUsername); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			m.templates.ExecuteTemplate(w, pageRecover, RecoverPage{username, confirmUsername, err.Error()})
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *RecoverModule) initiateRecover(ctx *authboss.Context, username, confirmUsername string) error {
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

	authboss.SendEmail("", "", []byte)

	return nil
}
