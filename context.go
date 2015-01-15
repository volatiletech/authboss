package authboss

import "net/http"

// Context provides context for module operations and callbacks. One obvious
// need for context is a request's session store. It is not safe for use by
// multiple goroutines.
type Context struct {
	SessionStorer ClientStorer
	CookieStorer  ClientStorer
	User          Attributes

	postFormValues map[string][]string
	formValues     map[string][]string
	keyValues      map[string]interface{}
}

func NewContext() *Context {
	return &Context{
		keyValues: make(map[string]interface{}),
	}
}

// ContextFromRequest creates a context from an http request.
func ContextFromRequest(r *http.Request) (*Context, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	c := NewContext()
	c.formValues = map[string][]string(r.Form)
	c.postFormValues = map[string][]string(r.PostForm)
	return c, nil
}

// Put an arbitrary key-value into the context.
func (c *Context) Put(key string, thing interface{}) {
	c.keyValues[key] = thing
}

// Get an arbitrary key-value from the context.
func (c *Context) Get(key string) (thing interface{}, ok bool) {
	thing, ok = c.keyValues[key]
	return thing, ok
}

// FormValue gets a form value from a context created with a request.
func (c *Context) FormValue(key string) ([]string, bool) {
	val, ok := c.formValues[key]
	return val, ok
}

// PostFormValue gets a form value from a context created with a request.
func (c *Context) PostFormValue(key string) ([]string, bool) {
	val, ok := c.postFormValues[key]
	return val, ok
}

// LoadUser loads the user Attributes if they haven't already been loaded.
func (c *Context) LoadUser(storer Storer) error {
	if c.User != nil {
		return nil
	}

	return nil
}
