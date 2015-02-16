package recover

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"gopkg.in/authboss.v0"
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
}

func (m *RecoverModule) Initialize() (err error) {
	if authboss.Cfg.Storer == nil {
		return errors.New("recover: Need a RecoverStorer.")
	}

	if _, ok := authboss.Cfg.Storer.(authboss.RecoverStorer); !ok {
		return errors.New("recover: RecoverStorer required for recover functionality.")
	}

	if authboss.Cfg.Layout == nil {
		return errors.New("recover: Layout required for Recover functionallity.")
	}
	if m.templates, err = views.Get(authboss.Cfg.Layout, authboss.Cfg.ViewsPath, tplRecover, tplRecoverComplete); err != nil {
		return err
	}

	if authboss.Cfg.LayoutEmail == nil {
		return errors.New("recover: LayoutEmail required for Recover functionallity.")
	}
	if m.emailTemplates, err = views.Get(authboss.Cfg.LayoutEmail, authboss.Cfg.ViewsPath, tplInitHTMLEmail, tplInitTextEmail); err != nil {
		return err
	}

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
		fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "unable to execute template", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := io.Copy(w, buffer); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
