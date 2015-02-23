package register

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

func TestRegister(t *testing.T) {
	authboss.Cfg = authboss.NewConfig()
	r := Register{}

	if err := r.Initialize(); err != nil {
		t.Error(err)
	}

	if r.Routes()["/register"] == nil {
		t.Error("Expected a register handler at /register.")
	}

	sto := r.Storage()
	if sto[authboss.Cfg.PrimaryID] != authboss.String {
		t.Error("Wanted primary ID to be a string.")
	}
	if sto[authboss.StorePassword] != authboss.String {
		t.Error("Wanted password to be a string.")
	}
}

func TestRegisterGet(t *testing.T) {
	authboss.Cfg = &authboss.Config{
		Layout:   template.Must(template.New("").Parse(`{{template "authboss"}}`)),
		XSRFName: "xsrf",
		XSRFMaker: func(_ http.ResponseWriter, _ *http.Request) string {
			return "xsrfvalue"
		},
	}
	reg := Register{}

	if err := reg.Initialize(); err != nil {
		t.Error(err)
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/register", nil)
	ctx, _ := authboss.ContextFromRequest(r)
	ctx.SessionStorer = mocks.NewMockClientStorer()

	if err := reg.registerHandler(ctx, w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("It should have written a 200:", w.Code)
	}

	if w.Body.Len() == 0 {
		t.Error("It should have wrote a response.")
	}

	if str := w.Body.String(); !strings.Contains(str, "<form") {
		t.Error("It should have rendered a nice form:", str)
	}
}
