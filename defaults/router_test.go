package defaults

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRouter(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	var get, post, del string
	wantGet, wantPost, wantDelete := "testget", "testpost", "testdelete"

	r.Get("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		get = string(b)
	}))
	r.Post("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		post = string(b)
	}))
	r.Delete("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		del = string(b)
	}))

	wr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", strings.NewReader("testget"))
	r.ServeHTTP(wr, req)
	if get != wantGet {
		t.Error("want:", wantGet, "got:", get)
	}
	if len(post) != 0 || len(del) != 0 {
		t.Error("should be empty:", post, del)
	}

	wr = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/test", strings.NewReader("testpost"))
	r.ServeHTTP(wr, req)
	if post != wantPost {
		t.Error("want:", wantPost, "got:", post)
	}
	if len(del) != 0 {
		t.Error("should be empty:", del)
	}

	wr = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/test", strings.NewReader("testdelete"))
	r.ServeHTTP(wr, req)
	if del != wantDelete {
		t.Error("want:", wantDelete, "got:", del)
	}
}

func TestRouterBadMethod(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	wr := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/", nil)

	r.ServeHTTP(wr, req)

	if wr.Code != http.StatusMethodNotAllowed {
		t.Error("want method not allowed code, got:", wr.Code)
	}
}
