package authboss

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestResponseRespond(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.renderer = mockRenderer{expectName: "some_template.tpl"}
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

	r := httptest.NewRequest("GET", "/", nil)
	wr := httptest.NewRecorder()
	w := ab.NewResponse(wr, r)
	r = loadClientStateP(ab, w, r)
	err := ab.Respond(w, r, http.StatusCreated, "some_template.tpl", HTMLData{"auth_happy": true})
	if err != nil {
		t.Error(err)
	}

	if wr.Code != http.StatusCreated {
		t.Error("code was wrong:", wr.Code)
	}

	if got := wr.HeaderMap.Get("Content-Type"); got != "application/json" {
		t.Error("content type was wrong:", got)
	}

	expectData := HTMLData{
		"xsrfName":      "xsrf",
		"xsrfToken":     "xsrftoken",
		"hello":         "world",
		FlashSuccessKey: "flash_success",
		FlashErrorKey:   "flash_error",
		"auth_happy":    true,
	}

	var gotData HTMLData
	if err := json.Unmarshal(wr.Body.Bytes(), &gotData); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(gotData, expectData) {
		t.Errorf("data mismatched:\nwant: %#v\ngot:  %#v", expectData, gotData)
	}
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
	ab.Mailer = LogMailer(output)

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

func TestResponseRedirectAPI(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.renderer = mockRenderer{}
	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	r.Header.Set("Content-Type", "application/json")

	ro := RedirectOptions{
		Success:      "ok!",
		Code:         http.StatusTeapot,
		RedirectPath: "/redirect", FollowRedirParam: false,
	}

	if err := ab.Redirect(w, r, ro); err != nil {
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

	ab := New()
	ab.renderer = mockRenderer{}
	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	w := httptest.NewRecorder()

	r.Header.Set("Content-Type", "application/json")

	ro := RedirectOptions{
		Failure:      ":(",
		Code:         http.StatusTeapot,
		RedirectPath: "/redirect", FollowRedirParam: true,
	}

	if err := ab.Redirect(w, r, ro); err != nil {
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

	ab := New()
	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	wr := httptest.NewRecorder()
	w := ab.NewResponse(wr, r)

	ro := RedirectOptions{
		Success: "success", Failure: "failure",
		RedirectPath: "/redirect", FollowRedirParam: false,
	}

	if err := ab.Redirect(w, r, ro); err != nil {
		t.Error(err)
	}

	csrw := w.(*ClientStateResponseWriter)
	want := ClientStateEvent{Kind: ClientStateEventPut, Key: FlashSuccessKey, Value: "success"}
	if csrw.sessionStateEvents[0] != want {
		t.Error("event was wrong:", csrw.sessionStateEvents[0])
	}
	want = ClientStateEvent{Kind: ClientStateEventPut, Key: FlashErrorKey, Value: "failure"}
	if csrw.sessionStateEvents[1] != want {
		t.Error("event was wrong:", csrw.sessionStateEvents[1])
	}
	if wr.Code != http.StatusFound {
		t.Error("code is wrong:", wr.Code)
	}
	if got := wr.Header().Get("Location"); got != "/redirect" {
		t.Error("redirect location was wrong:", got)
	}
}

func TestResponseRedirectNonAPIFollowRedir(t *testing.T) {
	t.Parallel()

	ab := New()
	r := httptest.NewRequest("POST", "/?redir=/pow", nil)
	wr := httptest.NewRecorder()
	w := ab.NewResponse(wr, r)

	ro := RedirectOptions{
		RedirectPath: "/redirect", FollowRedirParam: true,
	}
	if err := ab.Redirect(w, r, ro); err != nil {
		t.Error(err)
	}

	csrw := w.(*ClientStateResponseWriter)
	if len(csrw.sessionStateEvents) != 0 {
		t.Error("session state events should be empty:", csrw.sessionStateEvents)
	}
	if wr.Code != http.StatusFound {
		t.Error("code is wrong:", wr.Code)
	}
	if got := wr.Header().Get("Location"); got != "/pow" {
		t.Error("redirect location was wrong:", got)
	}
}
