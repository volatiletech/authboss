package recover

import (
	"errors"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"

	"gopkg.in/authboss.v0"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	pageRecover = "recover.tpl"

	attrUsername = "Username"
)

func init() {
	m := &RecoverModule{}
	authboss.RegisterModule("recover", m)
}

type RecoverPage struct {
	Username, Error string
}

type RecoverModule struct {
	templates      *template.Template
	routes         authboss.RouteTable
	storageOptions authboss.StorageOptions
	users          authboss.Storer
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
		attrUsername: authboss.String,
	}
	m.users = c.Storer

	return nil
}

func (m *RecoverModule) Routes() authboss.RouteTable {
	return m.routes
}

func (m *RecoverModule) Storage() authboss.StorageOptions {
	return m.storageOptions
}

func (m *RecoverModule) recoverHandlerFunc(c *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		m.templates.ExecuteTemplate(w, pageRecover, nil)
	case methodPOST:
		u := r.PostFormValue("username")
		cu := r.PostFormValue("confirmUsername")

		if err := recoverAccount(u, cu); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			m.templates.ExecuteTemplate(w, pageRecover, RecoverPage{u, err.Error()})
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func recoverAccount(username, confirmUsername string) error {
	if !strings.EqualFold(username, confirmUsername) {
		return errors.New("Confirm username does not match")
	}

	return nil
}
