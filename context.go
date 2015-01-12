package authboss

// Context provides context for module operations and callbacks. One obvious
// need for context is a request's session store. It is not safe for use by
// multiple goroutines.
type Context struct {
	SessionStorer ClientStorer
	CookieStorer  ClientStorer
	User          Attributes

	keyValues map[string]interface{}
}

func NewContext() *Context {
	return &Context{
		keyValues: make(map[string]interface{}),
	}
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
