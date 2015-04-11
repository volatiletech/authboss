package authboss

import (
	"net/http"
	"time"
)

var nowTime = time.Now

// TimeToExpiry returns zero if the user session is expired else the time until expiry.
func (a *Authboss) TimeToExpiry(w http.ResponseWriter, r *http.Request) time.Duration {
	return a.timeToExpiry(a.SessionStoreMaker(w, r))
}

func (a *Authboss) timeToExpiry(session ClientStorer) time.Duration {
	dateStr, ok := session.Get(SessionLastAction)
	if !ok {
		return a.ExpireAfter
	}

	date, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		panic("last_action is not a valid RFC3339 date")
	}

	remaining := date.Add(a.ExpireAfter).Sub(nowTime().UTC())
	if remaining > 0 {
		return remaining
	}

	return 0
}

// RefreshExpiry  updates the last action for the user, so he doesn't become expired.
func (a *Authboss) RefreshExpiry(w http.ResponseWriter, r *http.Request) {
	session := a.SessionStoreMaker(w, r)
	a.refreshExpiry(session)
}

func (a *Authboss) refreshExpiry(session ClientStorer) {
	session.Put(SessionLastAction, nowTime().UTC().Format(time.RFC3339))
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

// ServeHTTP removes the session if it's passed the expire time.
func (m expireMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := m.ab.SessionStoreMaker(w, r)
	if _, ok := session.Get(SessionKey); ok {
		ttl := m.ab.timeToExpiry(session)
		if ttl == 0 {
			session.Del(SessionKey)
			session.Del(SessionLastAction)
		} else {
			m.ab.refreshExpiry(session)
		}
	}

	m.next.ServeHTTP(w, r)
}
