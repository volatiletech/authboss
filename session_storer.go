package authboss

// SessionStorer must be implemented to satisfy certain modules (auth, remember primarily).
// It should be a secure storage of the session. This means if it represents a cookie storage
// these cookies should be signed in order to prevent tampering, or they should be encrypted.
type SessionStorer interface {
	Put(key string, value interface{})
	Get(key string) interface{}
}
