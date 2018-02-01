package authboss

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStateGet(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Storage.SessionState = newMockClientStateRW("one", "two")
	ab.Storage.CookieState = newMockClientStateRW("three", "four")

	r := httptest.NewRequest("GET", "/", nil)
	w := ab.NewResponse(httptest.NewRecorder(), r)

	var err error
	r, err = ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	if got, _ := GetSession(r, "one"); got != "two" {
		t.Error("session value was wrong:", got)
	}
	if got, _ := GetCookie(r, "three"); got != "four" {
		t.Error("cookie value was wrong:", got)
	}
}

func TestStateResponseWriterDoubleWritePanic(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Storage.SessionState = newMockClientStateRW("one", "two")

	r := httptest.NewRequest("GET", "/", nil)
	w := ab.NewResponse(httptest.NewRecorder(), r)

	w.WriteHeader(200)
	// Check this doesn't panic
	w.WriteHeader(200)

	defer func() {
		if recover() == nil {
			t.Error("expected a panic")
		}
	}()

	w.putClientState()
}

func TestStateResponseWriterLastSecondWriteWithPrevious(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Storage.SessionState = newMockClientStateRW("one", "two")
	ab.Storage.CookieState = newMockClientStateRW("three", "four")

	r := httptest.NewRequest("GET", "/", nil)
	var w http.ResponseWriter = httptest.NewRecorder()

	var err error
	r, err = ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}
	w = ab.NewResponse(w, r)

	w.WriteHeader(200)

	// This is an odd test, since the mock will always overwrite the previous
	// write with the cookie values. Keeping it anyway for code coverage
	got := strings.TrimSpace(w.Header().Get("test_session"))
	if got != `{"three":"four"}` {
		t.Error("got:", got)
	}
}

func TestStateResponseWriterLastSecondWriteHeader(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Storage.SessionState = newMockClientStateRW()

	r := httptest.NewRequest("GET", "/", nil)
	w := ab.NewResponse(httptest.NewRecorder(), r)

	PutSession(w, "one", "two")

	w.WriteHeader(200)
	got := strings.TrimSpace(w.Header().Get("test_session"))
	if got != `{"one":"two"}` {
		t.Error("got:", got)
	}
}

func TestStateResponseWriterLastSecondWriteWrite(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Storage.SessionState = newMockClientStateRW()

	r := httptest.NewRequest("GET", "/", nil)
	w := ab.NewResponse(httptest.NewRecorder(), r)

	PutSession(w, "one", "two")

	io.WriteString(w, "Hello world!")

	got := strings.TrimSpace(w.Header().Get("test_session"))
	if got != `{"one":"two"}` {
		t.Error("got:", got)
	}
}

func TestStateResponseWriterEvents(t *testing.T) {
	t.Parallel()

	ab := New()
	r := httptest.NewRequest("GET", "/", nil)
	w := ab.NewResponse(httptest.NewRecorder(), r)

	PutSession(w, "one", "two")
	DelSession(w, "one")
	DelCookie(w, "one")
	PutCookie(w, "two", "one")

	want := ClientStateEvent{Kind: ClientStateEventPut, Key: "one", Value: "two"}
	if got := w.sessionStateEvents[0]; got != want {
		t.Error("event was wrong", got)
	}

	want = ClientStateEvent{Kind: ClientStateEventDel, Key: "one"}
	if got := w.sessionStateEvents[1]; got != want {
		t.Error("event was wrong", got)
	}

	want = ClientStateEvent{Kind: ClientStateEventDel, Key: "one"}
	if got := w.cookieStateEvents[0]; got != want {
		t.Error("event was wrong", got)
	}

	want = ClientStateEvent{Kind: ClientStateEventPut, Key: "two", Value: "one"}
	if got := w.cookieStateEvents[1]; got != want {
		t.Error("event was wrong", got)
	}
}

func TestFlashClearer(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Storage.SessionState = newMockClientStateRW(FlashSuccessKey, "a", FlashErrorKey, "b")

	r := httptest.NewRequest("GET", "/", nil)
	w := ab.NewResponse(httptest.NewRecorder(), r)

	if msg := FlashSuccess(w, r); msg != "" {
		t.Error("Unexpected flash success:", msg)
	}

	if msg := FlashError(w, r); msg != "" {
		t.Error("Unexpected flash error:", msg)
	}

	var err error
	r, err = ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	if msg := FlashSuccess(w, r); msg != "a" {
		t.Error("Unexpected flash success:", msg)
	}

	if msg := FlashError(w, r); msg != "b" {
		t.Error("Unexpected flash error:", msg)
	}

	want := ClientStateEvent{Kind: ClientStateEventDel, Key: FlashSuccessKey}
	if got := w.sessionStateEvents[0]; got != want {
		t.Error("event was wrong", got)
	}
	want = ClientStateEvent{Kind: ClientStateEventDel, Key: FlashErrorKey}
	if got := w.sessionStateEvents[1]; got != want {
		t.Error("event was wrong", got)
	}
}
