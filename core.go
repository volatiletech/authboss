package authboss

import (
	"net/http"
)

type Routes map[string]http.HandlerFunc

type Modularizer interface {
	Initialize(Config) error
	Routes() Routes
	Storage()
}

func Register(m Modularizer) {

}
