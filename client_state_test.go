package authboss

import (
	"io"
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
	w := ab.NewResponse(httptest.NewRecorder())

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

	w := ab.NewResponse(httptest.NewRecorder())

	w.WriteHeader(200)
	// Check this doesn't panic
	w.WriteHeader(200)

	defer func() {
		if recover() == nil {
			t.Error("expected a panic")
		}
	}()

	_ = w.putClientState()
}

func TestStateResponseWriterLastSecondWriteHeader(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Storage.SessionState = newMockClientStateRW()

	w := ab.NewResponse(httptest.NewRecorder())

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

	w := ab.NewResponse(httptest.NewRecorder())

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
	w := ab.NewResponse(httptest.NewRecorder())

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
	w := ab.NewResponse(httptest.NewRecorder())

	if msg := FlashSuccess(w, r); msg != "" {
		t.Error("unexpected flash success:", msg)
	}

	if msg := FlashError(w, r); msg != "" {
		t.Error("unexpected flash error:", msg)
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

func TestDelKnown(t *testing.T) {
	t.Parallel()

	csrw := &ClientStateResponseWriter{}

	DelKnownSession(csrw)
	DelKnownCookie(csrw)

	mustBeDel := func(ev ClientStateEvent) {
		t.Helper()
		if ev.Kind != ClientStateEventDel {
			t.Error("events should all be deletes")
		}
	}

	if len(csrw.sessionStateEvents) != 3 {
		t.Error("should have deleted 3 session entries")
	}
	mustBeDel(csrw.sessionStateEvents[0])
	mustBeDel(csrw.sessionStateEvents[1])
	mustBeDel(csrw.sessionStateEvents[2])

	for i, key := range []string{SessionKey, SessionHalfAuthKey, SessionLastAction} {
		if sessionKey := csrw.sessionStateEvents[i].Key; key != sessionKey {
			t.Errorf("%d) key was wrong, want: %s, got: %s", i, key, sessionKey)
		}
	}

	if len(csrw.cookieStateEvents) != 1 {
		t.Error("should have deleted 1 cookie")
	}
	mustBeDel(csrw.cookieStateEvents[0])
	if key := csrw.cookieStateEvents[0].Key; key != CookieRemember {
		t.Error("cookie key was wrong:", key)
	}
}
