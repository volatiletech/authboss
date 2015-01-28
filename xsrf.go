package authboss

import "net/http"

// XSRF returns a token that should be written to forms to prevent xsrf attacks.
type XSRF func(http.ResponseWriter, *http.Request) (token string)
