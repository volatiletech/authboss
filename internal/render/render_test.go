package render

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
	"gopkg.in/authboss.v0/internal/views"
)

var testViewTemplate = template.Must(template.New("").Parse(`{{.external}} {{.fun}} {{.flash_success}} {{.flash_error}} {{.xsrfName}} {{.xsrfToken}}`))

func TestView(t *testing.T) {
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

	tpls := views.Templates{
		"hello": testViewTemplate,
	}

	err := View(ctx, w, r, tpls, "hello", authboss.HTMLData{"external": "there"})
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
