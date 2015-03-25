package authboss

import "net/http"

const (
	// SessionKey is the primarily used key by authboss.
	SessionKey = "uid"
	// SessionHalfAuthKey is used for sessions that have been authenticated by
	// the remember module. This serves as a way to force full authentication
	// by denying half-authed users acccess to sensitive areas.
	SessionHalfAuthKey = "halfauth"
	// SessionLastAction is the session key to retrieve the last action of a user.
	SessionLastAction = "last_action"
	// SessionOAuth2State is the xsrf protection key for oauth.
	SessionOAuth2State = "oauth2_state"
	// SessionOAuth2Params is the additional settings for oauth like redirection/remember.
	SessionOAuth2Params = "oauth2_params"

	// CookieRemember is used for cookies and form input names.
	CookieRemember = "rm"

	// FlashSuccessKey is used for storing sucess flash messages on the session
	FlashSuccessKey = "flash_success"
	// FlashErrorKey is used for storing sucess flash messages on the session
	FlashErrorKey = "flash_error"
)

// ClientStorer should be able to store values on the clients machine. Cookie and
// Session storers are built with this interface.
type ClientStorer interface {
	Put(key, value string)
	Get(key string) (string, bool)
	Del(key string)
}

// ClientStorerErr is a wrapper to return error values from failed Gets.
type ClientStorerErr interface {
	ClientStorer
	GetErr(key string) (string, error)
}

type clientStoreWrapper struct {
	ClientStorer
}

// GetErr returns a value or an error.
func (c clientStoreWrapper) GetErr(key string) (string, error) {
	str, ok := c.Get(key)
	if !ok {
		return str, ClientDataErr{key}
	}

	return str, nil
}

// CookieStoreMaker is used to create a cookie storer from an http request. Keep in mind
// security considerations for your implementation, Secure, HTTP-Only, etc flags.
type CookieStoreMaker func(http.ResponseWriter, *http.Request) ClientStorer

// SessionStoreMaker is used to create a session storer from an http request.
// It must be implemented to satisfy certain modules (auth, remember primarily).
// It should be a secure storage of the session. This means if it represents a cookie-based session
// storage these cookies should be signed in order to prevent tampering, or they should be encrypted.
type SessionStoreMaker func(http.ResponseWriter, *http.Request) ClientStorer

// FlashSuccess returns FlashSuccessKey from the session and removes it.
func FlashSuccess(w http.ResponseWriter, r *http.Request) string {
	storer := Cfg.SessionStoreMaker(w, r)
	msg, ok := storer.Get(FlashSuccessKey)
	if ok {
		storer.Del(FlashSuccessKey)
	}

	return msg
}

// FlashError returns FlashError from the session and removes it.
func FlashError(w http.ResponseWriter, r *http.Request) string {
	storer := Cfg.SessionStoreMaker(w, r)
	msg, ok := storer.Get(FlashErrorKey)
	if ok {
		storer.Del(FlashErrorKey)
	}

	return msg
}
