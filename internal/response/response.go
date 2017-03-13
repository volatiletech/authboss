// Package response is responsible for loading and rendering authboss templates.
package response

//go:generate go-bindata -pkg=response -prefix=templates templates

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/authboss.v1"
)

var (
	// ErrTemplateNotFound should be returned from Get when the view is not found
	ErrTemplateNotFound = errors.New("Template not found")
)

// Templates is a map depicting the forms a template needs wrapped within the specified layout
type Templates map[string]*template.Template

// LoadTemplates parses all specified files located in fpath. Each template is wrapped
// in a unique clone of layout.  All templates are expecting {{authboss}} handlebars
// for parsing. It will check the override directory specified in the config, replacing any
// templates as necessary.
func LoadTemplates(ab *authboss.Authboss, layout *template.Template, fpath string, files ...string) (Templates, error) {
	m := make(Templates)

	funcMap := template.FuncMap{
		"title": strings.Title,
		"mountpathed": func(location string) string {
			if ab.MountPath == "/" {
				return location
			}
			return path.Join(ab.MountPath, location)
		},
	}

	for _, file := range files {
		b, err := ioutil.ReadFile(filepath.Join(fpath, file))
		if exists := !os.IsNotExist(err); err != nil && exists {
			return nil, err
		} else if !exists {
			b, err = Asset(file)
			if err != nil {
				return nil, err
			}
		}

		clone, err := layout.Clone()
		if err != nil {
			return nil, err
		}

		_, err = clone.New("authboss").Funcs(funcMap).Parse(string(b))
		if err != nil {
			return nil, err
		}

		m[file] = clone
	}

	return m, nil
}

// Render renders a view with xsrf and flash attributes.
func (t Templates) Render(ctx *authboss.Context, w http.ResponseWriter, r *http.Request, name string, data authboss.HTMLData) error {
	tpl, ok := t[name]
	if !ok {
		return authboss.RenderErr{TemplateName: name, Data: data, Err: ErrTemplateNotFound}
	}

	data.MergeKV(
		"xsrfName", template.HTML(ctx.XSRFName),
		"xsrfToken", template.HTML(ctx.XSRFMaker(w, r)),
	)

	if ctx.LayoutDataMaker != nil {
		data.Merge(ctx.LayoutDataMaker(w, r))
	}

	if flash, ok := ctx.SessionStorer.Get(authboss.FlashSuccessKey); ok {
		ctx.SessionStorer.Del(authboss.FlashSuccessKey)
		data.MergeKV(authboss.FlashSuccessKey, flash)
	}
	if flash, ok := ctx.SessionStorer.Get(authboss.FlashErrorKey); ok {
		ctx.SessionStorer.Del(authboss.FlashErrorKey)
		data.MergeKV(authboss.FlashErrorKey, flash)
	}

	buffer := &bytes.Buffer{}
	err := tpl.ExecuteTemplate(buffer, tpl.Name(), data)
	if err != nil {
		return authboss.RenderErr{TemplateName: tpl.Name(), Data: data, Err: ErrTemplateNotFound}
	}

	_, err = io.Copy(w, buffer)
	if err != nil {
		return authboss.RenderErr{TemplateName: tpl.Name(), Data: data, Err: ErrTemplateNotFound}
	}

	return nil
}

// RenderEmail renders the html and plaintext views for an email and sends it
func Email(mailer authboss.Mailer, email authboss.Email, htmlTpls Templates, nameHTML string, textTpls Templates, namePlain string, data interface{}) error {
	tplHTML, ok := htmlTpls[nameHTML]
	if !ok {
		return authboss.RenderErr{TemplateName: tplHTML.Name(), Data: data, Err: ErrTemplateNotFound}
	}

	tplPlain, ok := textTpls[namePlain]
	if !ok {
		return authboss.RenderErr{TemplateName: tplPlain.Name(), Data: data, Err: ErrTemplateNotFound}
	}

	htmlBuffer := &bytes.Buffer{}
	if err := tplHTML.ExecuteTemplate(htmlBuffer, tplHTML.Name(), data); err != nil {
		return authboss.RenderErr{TemplateName: tplHTML.Name(), Data: data, Err: err}
	}
	email.HTMLBody = htmlBuffer.String()

	plainBuffer := &bytes.Buffer{}
	if err := tplPlain.ExecuteTemplate(plainBuffer, tplPlain.Name(), data); err != nil {
		return authboss.RenderErr{TemplateName: tplPlain.Name(), Data: data, Err: err}
	}
	email.TextBody = plainBuffer.String()

	if err := mailer.Send(email); err != nil {
		return err
	}

	return nil
}

// Redirect sets any flash messages given and redirects the user.
// If flashSuccess or flashError are set they will be set in the session.
// If followRedir is set to true, it will attempt to grab the redirect path from the
// query string.
func Redirect(ctx *authboss.Context, w http.ResponseWriter, r *http.Request, path, flashSuccess, flashError string, followRedir bool) {
	if redir := r.FormValue(authboss.FormValueRedirect); redir != "" && followRedir {
		path = redir
	}

	if len(flashSuccess) > 0 {
		ctx.SessionStorer.Put(authboss.FlashSuccessKey, flashSuccess)
	}
	if len(flashError) > 0 {
		ctx.SessionStorer.Put(authboss.FlashErrorKey, flashError)
	}
	http.Redirect(w, r, path, http.StatusFound)
}
