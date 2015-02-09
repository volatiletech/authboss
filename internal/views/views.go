// Package views is responsible for loading authboss templates.  It will check
// the override directory specified in the config, replace any tempaltes where
// need be.
package views

//go:generate go-bindata -pkg=views -prefix=templates templates

import (
	"bytes"
	"errors"
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	// ErrTemplateNotFound should be returned from Get when the view is not found
	ErrTemplateNotFound = errors.New("Template not found")
)

// Templates is a map depicting the forms a template needs wrapped within the specified layout
type Templates map[string]*template.Template

// ExecuteTemplate is a convenience wrapper for executing a template from the layout.  Returns
// ErrTemplateNotFound when the template is missing, othwerise error.
func (t Templates) ExecuteTemplate(name string, data interface{}) (buffer *bytes.Buffer, err error) {
	tpl, ok := t[name]
	if !ok {
		return nil, ErrTemplateNotFound
	}

	buffer = &bytes.Buffer{}
	err = tpl.ExecuteTemplate(buffer, tpl.Name(), data)

	return buffer, err
}

// Get parses all speicified files located in path.  Each template is wrapped
// in a unique clone of layout.  All templates are expecting {{authboss}} handlebars
// for parsing.
func Get(layout *template.Template, path string, files ...string) (Templates, error) {
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

// Asset parses a specified file from the internal bindata.
func AssetToTemplate(file string) (*template.Template, error) {
	b, err := Asset(file)
	if err != nil {
		return nil, err
	}

	return template.New("").Parse(string(b))
}
