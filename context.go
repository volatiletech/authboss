package authboss

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FormValue constants
var (
	FormValueRedirect    = "redir"
	FormValueOAuth2State = "state"
)

// Context provides context for module operations and callbacks. One obvious
// need for context is a request's session store. It is not safe for use by
// multiple goroutines.
type Context struct {
	SessionStorer ClientStorerErr
	CookieStorer  ClientStorerErr
	User          Attributes

	postFormValues map[string][]string
	formValues     map[string][]string
}

// NewContext is exported for testing modules.
func NewContext() *Context {
	return &Context{}
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

// FirstFormValueErr gets the first form value from a context created with a request
// and additionally returns an error not a bool if it's not found.
func (c *Context) FirstFormValueErr(key string) (string, error) {
	val, ok := c.formValues[key]

	if !ok || len(val) == 0 || len(val[0]) == 0 {
		return "", ClientDataErr{key}
	}

	return val[0], nil
}

// FirstPostFormValueErr gets the first form value from a context created with a request.
func (c *Context) FirstPostFormValueErr(key string) (string, error) {
	val, ok := c.postFormValues[key]

	if !ok || len(val) == 0 || len(val[0]) == 0 {
		return "", ClientDataErr{key}
	}

	return val[0], nil
}

// LoadUser loads the user Attributes if they haven't already been loaded.
func (c *Context) LoadUser(key string) error {
	if c.User != nil {
		return nil
	}

	var user interface{}
	var err error

	if index := strings.IndexByte(key, ';'); index > 0 {
		user, err = Cfg.OAuth2Storer.GetOAuth(key[:index], key[index+1:])
	} else {
		user, err = Cfg.Storer.Get(key)
	}
	if err != nil {
		return err
	}

	c.User = Unbind(user)
	return nil
}

// LoadSessionUser loads the user from the session if the user has not already been
// loaded.
func (c *Context) LoadSessionUser() error {
	if c.User != nil {
		return nil
	}

	key, ok := c.SessionStorer.Get(SessionKey)
	if !ok {
		return ErrUserNotFound
	}

	return c.LoadUser(key)
}

// SaveUser saves the user Attributes.
func (c *Context) SaveUser() error {
	if c.User == nil {
		return errors.New("User not initialized.")
	}

	key, ok := c.User.String(Cfg.PrimaryID)
	if !ok {
		return errors.New("User improperly initialized, primary ID missing")
	}

	return Cfg.Storer.Put(key, c.User)
}

// Attributes converts the post form values into an attributes map.
func (c *Context) Attributes() (Attributes, error) {
	attr := make(Attributes)

	for name, values := range c.postFormValues {
		if len(values) == 0 {
			continue
		}

		val := values[0]
		switch {
		case strings.HasSuffix(name, "_int"):
			integer, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("%q (%q): could not be converted to an integer: %v", name, val, err)
			}
			attr[strings.TrimRight(name, "_int")] = integer
		case strings.HasSuffix(name, "_date"):
			date, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return nil, fmt.Errorf("%q (%q): could not be converted to a datetime: %v", name, val, err)
			}
			attr[strings.TrimRight(name, "_date")] = date.UTC()
		default:
			attr[name] = val
		}
	}

	return attr, nil
}
