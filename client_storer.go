package authboss

import "net/http"

// SessionKey is the primarily used key by authboss.
const SessionKey = "uid"

// ClientStorer should be able to store values on the clients machine. Cookie and
// Session storers are built with this interface.
type ClientStorer interface {
	Put(key, value string)
	Get(key string) (string, bool)
}

// CookieStoreMaker is used to create a cookie storer from an http request. Keep in mind
// security considerations for your implementation, Secure, HTTP-Only, etc flags.
type CookieStoreMaker func(http.ResponseWriter, *http.Request) ClientStorer

// SessionStoreMaker is used to create a session storer from an http request.
// It must be implemented to satisfy certain modules (auth, remember primarily).
// It should be a secure storage of the session. This means if it represents a cookie-based session
// storage these cookies should be signed in order to prevent tampering, or they should be encrypted.
type SessionStoreMaker func(http.ResponseWriter, *http.Request) ClientStorer
