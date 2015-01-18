// Package views is responsible for loading authboss templates.  It will check
// the override directory specified in the config, replace any tempaltes where
// need be.
package views

//go:generate go-bindata -pkg=views -prefix=templates templates

import (
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Get all specified templates grouped under single template.
func Get(path string, files ...string) (*template.Template, error) {
	root := template.New("")

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

		_, err = root.New(file).Parse(string(b))
		if err != nil {
			return nil, err
		}
	}

	return root, nil
}
