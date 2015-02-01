package authboss

import "net/http"

// ViewDataMaker is set in the config and is called before
// template rendering to help correctly render the layout page.
type ViewDataMaker func(r *http.Request) ViewHelper

// ViewData is the data authboss uses for rendering a page.
// Typically this goes on your layout page's data struct.
type ViewData interface{}

// ViewHelper is a type that implements a Put() and Get() method for
// authboss's view data. Before a template is rendered
// by the authboss http handlers, it will call the config's ViewDataMaker
// callback to get a ViewHelper containing data that will be useful for the
// layout page, then use Put to set it, and inside the template use Get to get it.
type ViewHelper interface {
	Put(ViewData)
	Get() ViewData
}
