package main

import (
	"net/http"

	"log"

	"io"

	"bytes"

	"github.com/go-authboss/authboss"
	"github.com/go-authboss/authboss/auth"
)

func main() {
	a := &auth.Auth{}
	a.Initialize(authboss.Config{
		MountPath: "/",
	})

	mux := http.NewServeMux()

	for path, fn := range a.Routes() {
		mux.HandleFunc(path, fn)
	}

	mux.HandleFunc("/authboss.css", func(w http.ResponseWriter, r *http.Request) {
		if b, err := a.Style(); err != nil {
			log.Panicln(err)
		} else {
			io.Copy(w, bytes.NewBuffer(b))
		}
	})

	http.ListenAndServe("localhost:8080", mux)
}
