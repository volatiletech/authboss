package authboss

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testMailer struct {
	io.Writer
}

func (t testMailer) Send(_ context.Context, email Email) error {
	fmt.Fprintf(t.Writer, "%v", email)
	return nil
}

func TestResponseEmail(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.renderer = mockEmailRenderer{}
	ab.SessionStateStorer = newMockClientStateRW(
		FlashSuccessKey, "flash_success",
		FlashErrorKey, "flash_error",
	)
	ab.XSRFName = "xsrf"
	ab.XSRFMaker = func(w http.ResponseWriter, r *http.Request) string {
		return "xsrftoken"
	}
	ab.LayoutDataMaker = func(w http.ResponseWriter, r *http.Request) HTMLData {
		return HTMLData{"hello": "world"}
	}

	output := &bytes.Buffer{}
	ab.Mailer = testMailer{output}

	r := httptest.NewRequest("GET", "/", nil)
	wr := httptest.NewRecorder()
	w := ab.NewResponse(wr, r)

	email := Email{
		To:      []string{"test@example.com"},
		From:    "test@example.com",
		Subject: "subject",
	}
	ro := EmailResponseOptions{Data: nil, HTMLTemplate: "html", TextTemplate: "text"}
	err := ab.Email(w, r, email, ro)
	if err != nil {
		t.Error(err)
	}

	wantStrings := []string{
		"To: test@example.com",
		"From: test@example.com",
		"Subject: subject",
		"development text e-mail",
		"development html e-mail",
	}

	out := output.String()
	for i, test := range wantStrings {
		if !strings.Contains(out, test) {
			t.Errorf("output missing string(%d): %s\n%s", i, test, out)
		}
	}
}
