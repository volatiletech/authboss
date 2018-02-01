package defaults

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouter(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	var get, post, delete string
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

		delete = string(b)
	}))

	if get != wantGet {
		t.Error("want:", wantGet, "got:", get)
	}
	if post != wantPost {
		t.Error("want:", wantPost, "got:", post)
	}
	if delete != wantDelete {
		t.Error("want:", wantDelete, "got:", delete)
	}
}

func TestRouterBadMethod(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	wr := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/", nil)

	r.ServeHTTP(wr, req)

	if wr.Code != http.StatusBadRequest {
		t.Error("want bad request code, got:", wr.Code)
	}
}
