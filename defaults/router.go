package defaults

import (
	"io"
	"net/http"
)

// Router implementation
// Does not use a dynamic map to hope to be slightly more performant
type Router struct {
	gets    *http.ServeMux
	posts   *http.ServeMux
	deletes *http.ServeMux
}

// NewRouter creates a new router
func NewRouter() *Router {
	r := &Router{
		gets:    http.NewServeMux(),
		posts:   http.NewServeMux(),
		deletes: http.NewServeMux(),
	}

	// Nothing gets handled at the root of the authboss router
	r.gets.Handle("/", http.NotFoundHandler())
	r.posts.Handle("/", http.NotFoundHandler())
	r.deletes.Handle("/", http.NotFoundHandler())

	return r
}

// Get method route
func (r *Router) Get(path string, handler http.Handler) {
	r.gets.Handle(path, handler)
}

// Post method route
func (r *Router) Post(path string, handler http.Handler) {
	r.posts.Handle(path, handler)
}

// Delete method route
func (r *Router) Delete(path string, handler http.Handler) {
	r.deletes.Handle(path, handler)
}

// ServeHTTP for http.Handler
// Only does get/posts, all other request types are a bad request
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var router http.Handler
	switch req.Method {
	case "GET":
		router = r.gets
	case "POST":
		router = r.posts
	case "DELETE":
		router = r.deletes
	default:
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "bad request, this method not allowed")
		return
	}

	router.ServeHTTP(w, req)
}
