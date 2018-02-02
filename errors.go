package authboss

import (
	"net/http"
)

// ErrorHandler allows routing to http.HandlerFunc's that additionally
// return an error for a higher level error handling mechanism.
type ErrorHandler interface {
	Wrap(func(w http.ResponseWriter, r *http.Request) error) http.Handler
}
