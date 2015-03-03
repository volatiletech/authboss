package authboss

import (
	"net/http"
	"time"
)

var nowTime = time.Now

// TimeToExpiry returns zero if the user session is expired else the time until expiry.
func TimeToExpiry(w http.ResponseWriter, r *http.Request) time.Duration {
	return timeToExpiry(Cfg.SessionStoreMaker(w, r))
}

func timeToExpiry(session ClientStorer) time.Duration {
	dateStr, ok := session.Get(SessionLastAction)
	if !ok {
		return Cfg.ExpireAfter
	}

	date, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		panic("last_action is not a valid RFC3339 date")
	}

	remaining := date.Add(Cfg.ExpireAfter).Sub(nowTime().UTC())
	if remaining > 0 {
		return remaining
	}

	return 0
}

// RefreshExpiry  updates the last action for the user, so he doesn't become expired.
func RefreshExpiry(w http.ResponseWriter, r *http.Request) {
	session := Cfg.SessionStoreMaker(w, r)
	refreshExpiry(session)
}

func refreshExpiry(session ClientStorer) {
	session.Put(SessionLastAction, nowTime().UTC().Format(time.RFC3339))
}

type expireMiddleware struct {
	next http.Handler
}

// ExpireMiddleware ensures that the user's expiry information is kept up-to-date
// on each request. Deletes the SessionKey from the session if the user is
// expired (Cfg.ExpireAfter duration since SessionLastAction).
func ExpireMiddleware(next http.Handler) http.Handler {
	return expireMiddleware{next}
}

func (m expireMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := Cfg.SessionStoreMaker(w, r)
	if _, ok := session.Get(SessionKey); ok {
		ttl := timeToExpiry(session)
		if ttl == 0 {
			session.Del(SessionKey)
			session.Del(SessionLastAction)
		} else {
			refreshExpiry(session)
		}
	}

	m.next.ServeHTTP(w, r)
}
