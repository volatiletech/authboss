package authboss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExpireIsExpired(t *testing.T) {
	ab := New()
	ab.SessionStateStorer = newMockClientStateRW(
		SessionKey, "username",
		SessionLastAction, time.Now().UTC().Format(time.RFC3339),
	)

	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxKeyPID, "primaryid"))
	r = r.WithContext(context.WithValue(r.Context(), ctxKeyUser, struct{}{}))
	w := ab.NewResponse(httptest.NewRecorder(), r)
	r, err := ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	// No t.Parallel() - Also must be after refreshExpiry() call
	nowTime = func() time.Time {
		return time.Now().UTC().Add(ab.ExpireAfter * 2)
	}
	defer func() {
		nowTime = time.Now
	}()

	called := false
	hadUser := false
	m := ab.ExpireMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		if r.Context().Value(ctxKeyPID) != nil {
			hadUser = true
		}
		if r.Context().Value(ctxKeyUser) != nil {
			hadUser = true
		}
	}))

	m.ServeHTTP(w, r)

	if !called {
		t.Error("expected middleware to call handler")
	}
	if hadUser {
		t.Error("expected user not to be present")
	}

	want := ClientStateEvent{
		Kind: ClientStateEventDel,
		Key:  SessionKey,
	}
	if got := w.sessionStateEvents[0]; got != want {
		t.Error("want:", want, "got:", got)
	}
	want = ClientStateEvent{
		Kind: ClientStateEventDel,
		Key:  SessionLastAction,
	}
	if got := w.sessionStateEvents[1]; got != want {
		t.Error("want:", want, "got:", got)
	}
}

func TestExpireNotExpired(t *testing.T) {
	ab := New()
	ab.Config.ExpireAfter = time.Hour
	ab.SessionStateStorer = newMockClientStateRW(
		SessionKey, "username",
		SessionLastAction, time.Now().UTC().Format(time.RFC3339),
	)

	var err error

	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), ctxKeyPID, "primaryid"))
	r = r.WithContext(context.WithValue(r.Context(), ctxKeyUser, struct{}{}))
	w := ab.NewResponse(httptest.NewRecorder(), r)
	r, err = ab.LoadClientState(w, r)
	if err != nil {
		t.Error(err)
	}

	// No t.Parallel() - Also must be after refreshExpiry() call
	newTime := time.Now().UTC().Add(ab.ExpireAfter / 2)
	nowTime = func() time.Time {
		return newTime
	}
	defer func() {
		nowTime = time.Now
	}()

	called := false
	hadUser := true
	m := ab.ExpireMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		if r.Context().Value(ctxKeyPID) == nil {
			hadUser = false
		}
		if r.Context().Value(ctxKeyUser) == nil {
			hadUser = false
		}
	}))

	m.ServeHTTP(w, r)

	if !called {
		t.Error("expected middleware to call handler")
	}
	if !hadUser {
		t.Error("expected user to be present")
	}

	want := ClientStateEvent{
		Kind:  ClientStateEventPut,
		Key:   SessionLastAction,
		Value: newTime.Format(time.RFC3339),
	}

	if got := w.sessionStateEvents[0]; got != want {
		t.Error("want:", want, "got:", got)
	}
}

func TestExpireTimeToExpiry(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "/", nil)

	want := 5 * time.Second
	dur := TimeToExpiry(r, want)
	if dur != want {
		t.Error("duration was wrong:", dur)
	}
}

func TestExpireRefreshExpiry(t *testing.T) {
	t.Parallel()

	ab := New()
	r := httptest.NewRequest("GET", "/", nil)
	w := ab.NewResponse(httptest.NewRecorder(), r)

	RefreshExpiry(w, r)
	if got := w.sessionStateEvents[0].Kind; got != ClientStateEventPut {
		t.Error("wrong event:", got)
	}
	if got := w.sessionStateEvents[0].Key; got != SessionLastAction {
		t.Error("wrong key:", got)
	}
}
