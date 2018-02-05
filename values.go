package authboss

import "net/http"

// BodyReader reads data from the request
// and returns it in an abstract form.
// Typically used to decode JSON responses
// or Url Encoded request bodies.
//
// The first parameter is the page that this request
// was made on so we can tell what kind of JSON object
// or form was present as well as create the proper
// validation mechanisms.
//
// A typical example of this is taking the request
// and turning it into a JSON struct that knows how
// to validate itself and return certain fields.
type BodyReader interface {
	Read(page string, r *http.Request) (Validator, error)
}

// UserValuer gets a string from a map-like data structure
// Typically a decoded JSON or form auth request
type UserValuer interface {
	Validator

	GetPID() string
	GetPassword() string
}
