package authboss

import (
	"errors"
	"net/http"
	"strings"
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
	*Authboss

	SessionStorer ClientStorerErr
	CookieStorer  ClientStorerErr
	User          Attributes

	// Values is a free-form key-value store to pass data to callbacks
	Values map[string]string
}

// NewContext is exported for testing modules.
func (a *Authboss) NewContext() *Context {
	return &Context{
		Authboss: a,
	}
}

func (a *Authboss) InitContext(w http.ResponseWriter, r *http.Request) *Context {
	ctx := a.NewContext()

	if ctx.StoreMaker != nil {
		ctx.Storer = ctx.StoreMaker(w, r)
	}

	if ctx.OAuth2StoreMaker != nil {
		ctx.OAuth2Storer = ctx.OAuth2StoreMaker(w, r)
	}

	if ctx.LogWriteMaker != nil {
		ctx.LogWriter = ctx.LogWriteMaker(w, r)
	}

	if ctx.MailMaker != nil {
		ctx.Mailer = ctx.MailMaker(w, r)
	}

	ctx.SessionStorer = clientStoreWrapper{a.SessionStoreMaker(w, r)}
	ctx.CookieStorer = clientStoreWrapper{a.CookieStoreMaker(w, r)}

	return ctx
}

// LoadUser loads the user Attributes if they haven't already been loaded.
func (c *Context) LoadUser(key string) error {
	if c.User != nil {
		return nil
	}

	var user interface{}
	var err error

	if index := strings.IndexByte(key, ';'); index > 0 {
		user, err = c.OAuth2Storer.GetOAuth(key[:index], key[index+1:])
	} else {
		user, err = c.Storer.Get(key)
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

	key, ok := c.User.String(c.PrimaryID)
	if !ok {
		return errors.New("User improperly initialized, primary ID missing")
	}

	return c.Storer.Put(key, c.User)
}
