package views

import (
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestTemplates_ExecuteTemplate_ReturnsTemplateWhenFound(t *testing.T) {
	t.Parallel()

	tpl, _ := template.New("").Parse("<strong>{{.Val}}</strong>")
	tpls := Templates{"a": tpl}

	//b := &bytes.Buffer{}
	b, err := tpls.ExecuteTemplate("a", struct{ Val string }{"hi"})
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	expected := "<strong>hi</strong>"
	actual := b.String()
	if expected != actual {
		t.Errorf(`Expected "%s", got %s`, expected, actual)
	}
}

func TestTemplates_ExecuteTemplate_ReturnsErrTempalteNotFound(t *testing.T) {
	t.Parallel()

	tpls := Templates{}
	_, err := tpls.ExecuteTemplate("shouldnotbefound", nil)
	if err == nil {
		t.Error("Expected error")
	}

	if err.Error() != "Template not found" {
		t.Errorf(`Expected err.Error() to be "Template not found", got: "%s"`, err)
	}

}

func TestGet(t *testing.T) {
	t.Parallel()

	file, err := ioutil.TempFile(os.TempDir(), "authboss")
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if _, err := file.Write([]byte("{{.Val}}")); err != nil {
		t.Error("Error writing to temp file", err)
	}

	layout, err := template.New("").Parse(`<strong>{{template "authboss" .}}</strong>`)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	filename := filepath.Base(file.Name())

	tpls, err := Get(layout, filepath.Dir(file.Name()), filename)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	b, err := tpls.ExecuteTemplate(filename, struct{ Val string }{"hi"})
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	expected := "<strong>hi</strong>"
	actual := b.String()
	if expected != actual {
		t.Errorf(`Expected "%s", got %s`, expected, actual)
	}
}
