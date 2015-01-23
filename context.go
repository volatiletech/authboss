package authboss

import (
	"errors"
	"net/http"
)

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

// FirstFormValue gets the first form value from a context created with a request.
func (c *Context) FirstFormValue(key string) (string, bool) {
	val, ok := c.formValues[key]

	if !ok || len(val) == 0 || len(val[0]) == 0 {
		return "", false
	}

	return val[0], ok
}

// FirstPostFormValue gets the first form value from a context created with a request.
func (c *Context) FirstPostFormValue(key string) (string, bool) {
	val, ok := c.postFormValues[key]

	if !ok || len(val) == 0 || len(val[0]) == 0 {
		return "", false
	}

	return val[0], ok
}

// LoadUser loads the user Attributes if they haven't already been loaded.
func (c *Context) LoadUser(key string, storer Storer) error {
	if c.User != nil {
		return nil
	}

	intf, err := storer.Get(key, ModuleAttrMeta)
	if err != nil {
		return err
	}

	c.User = Unbind(intf)
	return nil
}

// SaveUser saves the user Attributes.
func (c *Context) SaveUser(key string, storer Storer) error {
	if c.User == nil {
		return errors.New("User not initialized.")
	}

	return storer.Put(key, c.User)
}
