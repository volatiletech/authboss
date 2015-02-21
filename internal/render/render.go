// Package render is responsible for loading and rendering authboss templates.
package render

//go:generate go-bindata -pkg=render -prefix=templates templates

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/authboss.v0"
)

var (
	// ErrTemplateNotFound should be returned from Get when the view is not found
	ErrTemplateNotFound = errors.New("Template not found")
)

// Templates is a map depicting the forms a template needs wrapped within the specified layout
type Templates map[string]*template.Template

// LoadTemplates parses all specified files located in path.  Each template is wrapped
// in a unique clone of layout.  All templates are expecting {{authboss}} handlebars
// for parsing. It will check the override directory specified in the config, replacing any
// templates as necessary.
func LoadTemplates(layout *template.Template, path string, files ...string) (Templates, error) {
	m := make(Templates)

	for _, file := range files {
		b, err := ioutil.ReadFile(filepath.Join(path, file))
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

		_, err = clone.New("authboss").Parse(string(b))
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
		return authboss.RenderErr{tpl.Name(), data, ErrTemplateNotFound}
	}

	data.MergeKV("xsrfName", template.HTML(authboss.Cfg.XSRFName), "xsrfToken", template.HTML(authboss.Cfg.XSRFMaker(w, r)))

	if authboss.Cfg.LayoutDataMaker != nil {
		data.Merge(authboss.Cfg.LayoutDataMaker(w, r))
	}

	if flash, ok := ctx.CookieStorer.Get(authboss.FlashSuccessKey); ok {
		ctx.CookieStorer.Del(authboss.FlashSuccessKey)
		data.MergeKV(authboss.FlashSuccessKey, flash)
	}
	if flash, ok := ctx.CookieStorer.Get(authboss.FlashErrorKey); ok {
		ctx.CookieStorer.Del(authboss.FlashErrorKey)
		data.MergeKV(authboss.FlashErrorKey, flash)
	}

	buffer := &bytes.Buffer{}
	err := tpl.ExecuteTemplate(buffer, tpl.Name(), data)
	if err != nil {
		return authboss.RenderErr{tpl.Name(), data, err}
	}

	_, err = io.Copy(w, buffer)
	if err != nil {
		return authboss.RenderErr{tpl.Name(), data, err}
	}

	return nil
}

// Redirect sets any flash messages given and redirects the user.
func Redirect(ctx *authboss.Context, w http.ResponseWriter, r *http.Request, path, flashSuccess, flashError string) {
	if len(flashSuccess) > 0 {
		ctx.CookieStorer.Put(authboss.FlashSuccessKey, flashSuccess)
	}
	if len(flashError) > 0 {
		ctx.CookieStorer.Put(authboss.FlashErrorKey, flashError)
	}
	http.Redirect(w, r, path, http.StatusTemporaryRedirect)
}
