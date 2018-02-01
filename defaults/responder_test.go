package defaults

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
)

type testRenderer struct {
	Callback func(context.Context, string, authboss.HTMLData) ([]byte, string, error)
}

func (t testRenderer) Render(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
	return t.Callback(ctx, name, data)
}

func TestResponder(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: func(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
			return nil, "", nil
		},
	}

	responder := Responder{
		Renderer:  renderer,
		CSRFName:  "csrf",
		CSRFMaker: func(w http.ResponseWriter, r *http.Request) string { return "csrftoken" },
	}

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	err := responder.Respond(w, r, http.StatusCreated, "some_template.tpl", authboss.HTMLData{"auth_happy": true})
	if err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusCreated {
		t.Error("code was wrong:", w.Code)
	}

	if got := w.HeaderMap.Get("Content-Type"); got != "application/json" {
		t.Error("content type was wrong:", got)
	}

	expectData := authboss.HTMLData{
		"csrfName":   "xsrf",
		"csrfToken":  "xsrftoken",
		"hello":      "world",
		"auth_happy": true,
	}

	var gotData authboss.HTMLData
	if err := json.Unmarshal(w.Body.Bytes(), &gotData); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(gotData, expectData) {
		t.Errorf("data mismatched:\nwant: %#v\ngot:  %#v", expectData, gotData)
	}
}
func TestRedirector(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: func(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
			return nil, "", nil
		},
	}

	redir := Redirector{
		FormValueName: "redir",
		Renderer:      renderer,
	}

	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	r.Header.Set("Content-Type", "application/json")

	ro := authboss.RedirectOptions{
		Success:      "ok!",
		Code:         http.StatusTeapot,
		RedirectPath: "/redirect", FollowRedirParam: false,
	}

	if err := redir.Redirect(w, r, ro); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTeapot {
		t.Error("code is wrong:", w.Code)
	}

	var gotData map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &gotData); err != nil {
		t.Error(err)
	}

	if got := gotData["status"]; got != "success" {
		t.Error("status was wrong:", got)
	}
	if got := gotData["message"]; got != "ok!" {
		t.Error("message was wrong:", got)
	}
	if got := gotData["location"]; got != "/redirect" {
		t.Error("location was wrong:", got)
	}
}

func TestResponseRedirectAPIFollowRedir(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: func(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
			return nil, "", nil
		},
	}

	redir := Redirector{
		FormValueName: "redir",
		Renderer:      renderer,
	}

	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	r.Header.Set("Content-Type", "application/json")

	ro := authboss.RedirectOptions{
		Failure:      ":(",
		Code:         http.StatusTeapot,
		RedirectPath: "/redirect", FollowRedirParam: true,
	}

	if err := redir.Redirect(w, r, ro); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTeapot {
		t.Error("code is wrong:", w.Code)
	}

	var gotData map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &gotData); err != nil {
		t.Error(err)
	}

	if got := gotData["status"]; got != "failure" {
		t.Error("status was wrong:", got)
	}
	if got := gotData["message"]; got != ":(" {
		t.Error("message was wrong:", got)
	}
	if got := gotData["location"]; got != "/pow" {
		t.Error("location was wrong:", got)
	}
}

func TestResponseRedirectNonAPI(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: func(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
			return nil, "", nil
		},
	}

	redir := Redirector{
		FormValueName: "redir",
		Renderer:      renderer,
	}

	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	ab := authboss.New()
	ab.Config.SessionStateStorer = mocks.NewClientRW()
	ab.Config.CookieStateStorer = mocks.NewClientRW()
	aw := ab.NewResponse(w, r)

	ro := authboss.RedirectOptions{
		Success: "success", Failure: "failure",
		RedirectPath: "/redirect", FollowRedirParam: false,
	}

	if err := redir.Redirect(aw, r, ro); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusFound {
		t.Error("code is wrong:", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/redirect" {
		t.Error("redirect location was wrong:", got)
	}
}

func TestResponseRedirectNonAPIFollowRedir(t *testing.T) {
	t.Parallel()

	renderer := testRenderer{
		Callback: func(ctx context.Context, name string, data authboss.HTMLData) ([]byte, string, error) {
			return nil, "", nil
		},
	}

	redir := Redirector{
		FormValueName: "redir",
		Renderer:      renderer,
	}

	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	ab := authboss.New()
	ab.Config.SessionStateStorer = mocks.NewClientRW()
	ab.Config.CookieStateStorer = mocks.NewClientRW()
	aw := ab.NewResponse(w, r)

	ro := authboss.RedirectOptions{
		RedirectPath: "/redirect", FollowRedirParam: true,
	}
	if err := redir.Redirect(aw, r, ro); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusFound {
		t.Error("code is wrong:", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/pow" {
		t.Error("redirect location was wrong:", got)
	}
}
