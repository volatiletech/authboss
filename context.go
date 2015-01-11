package authboss

// Context provides context for module operations and callbacks. One obvious
// need for context is a request's session store. It is not safe for use by
// multiple goroutines.
type Context struct {
	ClientStorer ClientStorer
	User         Attributes

	keyValues map[string]interface{}
}

func NewContext() *Context {
	return &Context{
		keyValues: make(map[string]interface{}),
	}
}

func (c *Context) Put(key string, thing interface{}) {
	c.keyValues[key] = thing
}

func (c *Context) Get(key string) (thing interface{}, ok bool) {
	thing, ok = c.keyValues[key]
	return thing, ok
}
