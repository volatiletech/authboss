package render

import (
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

var testViewTemplate = template.Must(template.New("").Parse(`{{.external}} {{.fun}} {{.flash_success}} {{.flash_error}} {{.xsrfName}} {{.xsrfToken}}`))

func TestLoadTemplates(t *testing.T) {
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

	tpls, err := LoadTemplates(layout, filepath.Dir(file.Name()), filename)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if len(tpls) != 1 {
		t.Error("Expected 1 template:", len(tpls))
	}

	if _, ok := tpls[filename]; !ok {
		t.Error("Expected tpl with name:", filename)
	}
}

func TestTemplates_Render(t *testing.T) {
	cookies := mocks.NewMockClientStorer()
	authboss.Cfg = &authboss.Config{
		LayoutDataMaker: func(_ http.ResponseWriter, _ *http.Request) authboss.HTMLData {
			return authboss.HTMLData{"fun": "is"}
		},
		XSRFName: "do you think",
		XSRFMaker: func(_ http.ResponseWriter, _ *http.Request) string {
			return "that's air you're breathing now?"
		},
	}

	// Set up flashes
	cookies.Put(authboss.FlashSuccessKey, "no")
	cookies.Put(authboss.FlashErrorKey, "spoon")

	r, _ := http.NewRequest("GET", "http://localhost", nil)
	w := httptest.NewRecorder()
	ctx, _ := authboss.ContextFromRequest(r)
	ctx.CookieStorer = cookies

	tpls := Templates{
		"hello": testViewTemplate,
	}

	err := tpls.Render(ctx, w, r, "hello", authboss.HTMLData{"external": "there"})
	if err != nil {
		t.Error(err)
	}

	if w.Body.String() != "there is no spoon do you think that's air you're breathing now?" {
		t.Error("Body was wrong:", w.Body.String())
	}
}

func TestRedirect(t *testing.T) {
	cookies := mocks.NewMockClientStorer()

	r, _ := http.NewRequest("GET", "http://localhost", nil)
	w := httptest.NewRecorder()
	ctx, _ := authboss.ContextFromRequest(r)
	ctx.CookieStorer = cookies

	Redirect(ctx, w, r, "/", "success", "failure")

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("Expected a redirect.")
	}

	if w.Header().Get("Location") != "/" {
		t.Error("Expected to be redirected to root.")
	}

	if val, _ := cookies.Get(authboss.FlashSuccessKey); val != "success" {
		t.Error("Flash success msg wrong:", val)
	}
	if val, _ := cookies.Get(authboss.FlashErrorKey); val != "failure" {
		t.Error("Flash failure msg wrong:", val)
	}
}
