package authboss

import (
	"context"
	"net/http"
	"time"
)

var nowTime = time.Now

// TimeToExpiry returns zero if the user session is expired else the time
// until expiry. Takes in the allowed idle duration.
func TimeToExpiry(r *http.Request, expireAfter time.Duration) time.Duration {
	return timeToExpiry(r, expireAfter)
}

func timeToExpiry(r *http.Request, expireAfter time.Duration) time.Duration {
	dateStr, ok := GetSession(r, SessionLastAction)
	if !ok {
		return expireAfter
	}

	date, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		panic("last_action is not a valid RFC3339 date")
	}

	remaining := date.Add(expireAfter).Sub(nowTime().UTC())
	if remaining > 0 {
		return remaining
	}

	return 0
}

// RefreshExpiry updates the last action for the user, so he doesn't
// become expired.
func RefreshExpiry(w http.ResponseWriter, r *http.Request) {
	refreshExpiry(w)
}

func refreshExpiry(w http.ResponseWriter) {
	PutSession(w, SessionLastAction, nowTime().UTC().Format(time.RFC3339))
}

type expireMiddleware struct {
	ab   *Authboss
	next http.Handler
}

// ExpireMiddleware ensures that the user's expiry information is kept up-to-date
// on each request. Deletes the SessionKey from the session if the user is
// expired (a.ExpireAfter duration since SessionLastAction).
// This middleware conflicts with use of the Remember module, don't enable both
// at the same time.
func (a *Authboss) ExpireMiddleware(next http.Handler) http.Handler {
	return expireMiddleware{a, next}
}

// ServeHTTP removes the session and hides the loaded user from the handlers
// below it.
func (m expireMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := GetSession(r, SessionKey); ok {
		ttl := timeToExpiry(r, m.ab.Modules.ExpireAfter)
		if ttl == 0 {
			DelSession(w, SessionKey)
			DelSession(w, SessionLastAction)
			ctx := context.WithValue(r.Context(), ctxKeyPID, nil)
			ctx = context.WithValue(ctx, ctxKeyUser, nil)
			r = r.WithContext(ctx)
		} else {
			refreshExpiry(w)
		}
	}

	m.next.ServeHTTP(w, r)
}
