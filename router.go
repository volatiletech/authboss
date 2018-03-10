package authboss

import (
	"net/http"
)

// Router can register routes to later be used by the web application
type Router interface {
	http.Handler

	Get(path string, handler http.Handler)
	Post(path string, handler http.Handler)
	Delete(path string, handler http.Handler)
}
