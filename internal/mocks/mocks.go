// Package mocks defines implemented interfaces for testing modules
package mocks

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
)

// User represents all possible fields a authboss User may have
type User struct {
	Username           string
	Email              string
	Password           string
	RecoverToken       string
	RecoverTokenExpiry time.Time
	ConfirmToken       string
	Confirmed          bool
	AttemptCount       int
	LastAttempt        time.Time
	Locked             time.Time
	OAuthToken         string
	OAuthRefresh       string
	OAuthExpiry        time.Time

	Arbitrary map[string]string
}

func (m User) GetPID() string                  { return m.Email }
func (m User) GetEmail() string                { return m.Email }
func (m User) GetUsername() string             { return m.Username }
func (m User) GetPassword() string             { return m.Password }
func (m User) GetRecoverToken() string         { return m.RecoverToken }
func (m User) GetRecoverExpiry() time.Time     { return m.RecoverTokenExpiry }
func (m User) GetConfirmToken() string         { return m.ConfirmToken }
func (m User) GetConfirmed() bool              { return m.Confirmed }
func (m User) GetAttemptCount() int            { return m.AttemptCount }
func (m User) GetLastAttempt() time.Time       { return m.LastAttempt }
func (m User) GetLocked() time.Time            { return m.Locked }
func (m User) GetOAuthToken() string           { return m.OAuthToken }
func (m User) GetOAuthRefresh() string         { return m.OAuthRefresh }
func (m User) GetOAuthExpiry() time.Time       { return m.OAuthExpiry }
func (m User) GetArbitrary() map[string]string { return m.Arbitrary }

func (m *User) PutPID(email string)                 { m.Email = email }
func (m *User) PutUsername(username string)         { m.Username = username }
func (m *User) PutEmail(email string)               { m.Email = email }
func (m *User) PutPassword(password string)         { m.Password = password }
func (m *User) PutRecoverToken(recoverToken string) { m.RecoverToken = recoverToken }
func (m *User) PutRecoverExpiry(recoverTokenExpiry time.Time) {
	m.RecoverTokenExpiry = recoverTokenExpiry
}
func (m *User) PutConfirmToken(confirmToken string)  { m.ConfirmToken = confirmToken }
func (m *User) PutConfirmed(confirmed bool)          { m.Confirmed = confirmed }
func (m *User) PutAttemptCount(attemptCount int)     { m.AttemptCount = attemptCount }
func (m *User) PutLastAttempt(attemptTime time.Time) { m.LastAttempt = attemptTime }
func (m *User) PutLocked(locked time.Time)           { m.Locked = locked }
func (m *User) PutOAuthToken(oAuthToken string)      { m.OAuthToken = oAuthToken }
func (m *User) PutOAuthRefresh(oAuthRefresh string)  { m.OAuthRefresh = oAuthRefresh }
func (m *User) PutOAuthExpiry(oAuthExpiry time.Time) { m.OAuthExpiry = oAuthExpiry }
func (m *User) PutArbitrary(arb map[string]string)   { m.Arbitrary = arb }

// ServerStorer should be valid for any module storer defined in authboss.
type ServerStorer struct {
	Users    map[string]*User
	RMTokens map[string][]string
}

// NewServerStorer constructor
func NewServerStorer() *ServerStorer {
	return &ServerStorer{
		Users:    make(map[string]*User),
		RMTokens: make(map[string][]string),
	}
}

// New constructs a blank user to later be created
func (s *ServerStorer) New(context.Context) authboss.User {
	return &User{}
}

// Create a user
func (s *ServerStorer) Create(ctx context.Context, user authboss.User) error {
	u := user.(*User)
	if _, ok := s.Users[u.Email]; ok {
		return authboss.ErrUserFound
	}
	s.Users[u.Email] = u
	return nil
}

// Load a user
func (s *ServerStorer) Load(ctx context.Context, key string) (authboss.User, error) {
	user, ok := s.Users[key]
	if ok {
		return user, nil
	}

	return nil, authboss.ErrUserNotFound
}

// Save a user
func (s *ServerStorer) Save(ctx context.Context, user authboss.User) error {
	u := user.(*User)
	if _, ok := s.Users[u.Email]; !ok {
		return authboss.ErrUserNotFound
	}
	s.Users[u.Email] = u
	return nil
}

// LoadByConfirmToken finds a user by his confirm token
func (s *ServerStorer) LoadByConfirmToken(ctx context.Context, token string) (authboss.ConfirmableUser, error) {
	for _, v := range s.Users {
		if v.ConfirmToken == token {
			return v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// LoadByRecoverToken finds a user by his recover token
func (s *ServerStorer) LoadByRecoverToken(ctx context.Context, token string) (authboss.RecoverableUser, error) {
	for _, v := range s.Users {
		if v.RecoverToken == token {
			return v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// AddRememberToken for remember me
func (s *ServerStorer) AddRememberToken(key, token string) error {
	arr := s.RMTokens[key]
	s.RMTokens[key] = append(arr, token)
	return nil
}

// DelRememberTokens for a user
func (s *ServerStorer) DelRememberTokens(key string) error {
	delete(s.RMTokens, key)
	return nil
}

// UseRememberToken if it exists, deleting it in the process
func (s *ServerStorer) UseRememberToken(givenKey, token string) (err error) {
	if arr, ok := s.RMTokens[givenKey]; ok {
		for _, tok := range arr {
			if tok == token {
				delete(s.RMTokens, givenKey)
				return nil
			}
		}
	}

	return authboss.ErrTokenNotFound
}

// FailStorer is used for testing module initialize functions that recover more than the base storer
type FailStorer struct {
	User
}

// Create fails
func (FailStorer) Create(context.Context) error {
	return errors.New("fail storer: create")
}

// Save fails
func (FailStorer) Save(context.Context) error {
	return errors.New("fail storer: put")
}

// Load fails
func (FailStorer) Load(context.Context) error {
	return errors.New("fail storer: get")
}

// ClientState is used for testing the client stores on context
type ClientState struct {
	Values        map[string]string
	GetShouldFail bool
}

// NewClientState constructs a ClientStorer
func NewClientState(data ...string) *ClientState {
	if len(data) != 0 && len(data)%2 != 0 {
		panic("It should be a key value list of arguments.")
	}

	values := make(map[string]string)

	for i := 0; i < len(data)-1; i += 2 {
		values[data[i]] = data[i+1]
	}

	return &ClientState{Values: values}
}

// Get a key's value
func (m *ClientState) Get(key string) (string, bool) {
	if m.GetShouldFail {
		return "", false
	}

	v, ok := m.Values[key]
	return v, ok
}

// Put a value
func (m *ClientState) Put(key, val string) { m.Values[key] = val }

// Del a key/value pair
func (m *ClientState) Del(key string) { delete(m.Values, key) }

// ClientStateRW stores things that would originally
// go in a session, or a map, in memory!
type ClientStateRW struct {
	ClientValues map[string]string
}

// NewClientRW takes the data from a client state
// and returns.
func NewClientRW() *ClientStateRW {
	return &ClientStateRW{
		ClientValues: make(map[string]string),
	}
}

// ReadState from memory
func (c *ClientStateRW) ReadState(*http.Request) (authboss.ClientState, error) {
	return &ClientState{Values: c.ClientValues}, nil
}

// WriteState to memory
func (c *ClientStateRW) WriteState(w http.ResponseWriter, cstate authboss.ClientState, cse []authboss.ClientStateEvent) error {
	for _, e := range cse {
		switch e.Kind {
		case authboss.ClientStateEventPut:
			c.ClientValues[e.Key] = e.Value
		case authboss.ClientStateEventDel:
			delete(c.ClientValues, e.Key)
		}
	}

	return nil
}

// Request returns a new request with optional key-value body (form-post)
func Request(method string, postKeyValues ...string) *http.Request {
	var body io.Reader
	location := "http://localhost"

	if len(postKeyValues) > 0 {
		urlValues := make(url.Values)
		for i := 0; i < len(postKeyValues); i += 2 {
			urlValues.Set(postKeyValues[i], postKeyValues[i+1])
		}

		if method == "POST" || method == "PUT" {
			body = strings.NewReader(urlValues.Encode())
		} else {
			location += "?" + urlValues.Encode()
		}
	}

	req, err := http.NewRequest(method, location, body)
	if err != nil {
		panic(err.Error())
	}

	if len(postKeyValues) > 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return req
}

// Mailer helps simplify mailer testing by storing the last sent email
type Mailer struct {
	Last    authboss.Email
	SendErr string
}

// NewMailer constructs a  mailer
func NewMailer() *Mailer {
	return &Mailer{}
}

// Send an e-mail
func (m *Mailer) Send(ctx context.Context, email authboss.Email) error {
	if len(m.SendErr) > 0 {
		return errors.New(m.SendErr)
	}

	m.Last = email
	return nil
}

// AfterCallback is a callback that knows if it was called
type AfterCallback struct {
	HasBeenCalled bool
	Fn            authboss.EventHandler
}

// NewAfterCallback constructs a new aftercallback.
func NewAfterCallback() *AfterCallback {
	m := AfterCallback{}

	m.Fn = func(http.ResponseWriter, *http.Request, bool) (bool, error) {
		m.HasBeenCalled = true
		return false, nil
	}

	return &m
}

// Renderer mock
type Renderer struct {
	Pages []string

	// Render call variables
	Context context.Context
	Page    string
	Data    authboss.HTMLData
}

// HasLoadedViews ensures the views were loaded
func (r *Renderer) HasLoadedViews(pages ...string) error {
	if len(r.Pages) != len(pages) {
		return errors.Errorf("want: %d loaded views, got: %d", len(pages), len(r.Pages))
	}

	for i, want := range pages {
		got := r.Pages[i]
		if want != got {
			return errors.Errorf("want: %s [%d], got: %s", want, i, got)
		}
	}

	return nil
}

// Load nothing but store the pages that were loaded
func (r *Renderer) Load(pages ...string) error {
	r.Pages = append(r.Pages, pages...)
	return nil
}

// Render nothing, but record the arguments into the renderer
func (r *Renderer) Render(ctx context.Context, page string, data authboss.HTMLData) ([]byte, string, error) {
	r.Context = ctx
	r.Page = page
	r.Data = data
	return nil, "text/html", nil
}

// Responder records how a request was responded to
type Responder struct {
	Status int
	Page   string
	Data   authboss.HTMLData
}

// Respond stores the arguments in the struct
func (r *Responder) Respond(w http.ResponseWriter, req *http.Request, code int, page string, data authboss.HTMLData) error {
	r.Status = code
	r.Page = page
	r.Data = data

	return nil
}

// Redirector stores the redirect options passed to it and writes the Code
// to the ResponseWriter.
type Redirector struct {
	Options authboss.RedirectOptions
}

// Redirect a request
func (r *Redirector) Redirect(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	r.Options = ro
	if len(ro.RedirectPath) == 0 {
		panic("no redirect path on redirect call")
	}
	http.Redirect(w, req, ro.RedirectPath, ro.Code)
	return nil
}

// Emailer that holds the options it was given
type Emailer struct {
	Email authboss.Email
}

// Send an e-mail
func (e *Emailer) Send(ctx context.Context, email authboss.Email) error {
	e.Email = email
	return nil
}

// BodyReader reads the body of a request and returns some values
type BodyReader struct {
	Return authboss.Validator
}

// Read the return values
func (b BodyReader) Read(page string, r *http.Request) (authboss.Validator, error) {
	return b.Return, nil
}

// Values is returned from the BodyReader
type Values struct {
	PID      string
	Password string
	Token    string
	Remember bool

	Errors []error
}

// GetPID from values
func (v Values) GetPID() string {
	return v.PID
}

// GetPassword from values
func (v Values) GetPassword() string {
	return v.Password
}

// GetToken from values
func (v Values) GetToken() string {
	return v.Token
}

// GetShouldRemember gets the value that tells
// the remember module if it should remember the user
func (v Values) GetShouldRemember() bool {
	return v.Remember
}

// Validate the values
func (v Values) Validate() []error {
	return v.Errors
}

// ArbValues is arbitrary value storage
type ArbValues struct {
	Values map[string]string
	Errors []error
}

// GetPID gets the pid
func (a ArbValues) GetPID() string {
	return a.Values["email"]
}

// GetPassword gets the password
func (a ArbValues) GetPassword() string {
	return a.Values["password"]
}

// GetValues returns all values
func (a ArbValues) GetValues() map[string]string {
	return a.Values
}

// Validate nothing
func (a ArbValues) Validate() []error {
	return a.Errors
}

// Logger logs to the void
type Logger struct {
}

// Info logging
func (l Logger) Info(string) {}

// Error logging
func (l Logger) Error(string) {}

// Router records the routes that were registered
type Router struct {
	Gets    []string
	Posts   []string
	Deletes []string
}

// ServeHTTP does nothing
func (Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
}

// Get records the path in the router
func (r *Router) Get(path string, _ http.Handler) {
	r.Gets = append(r.Gets, path)
}

// Post records the path in the router
func (r *Router) Post(path string, _ http.Handler) {
	r.Posts = append(r.Posts, path)
}

// Delete records the path in the router
func (r *Router) Delete(path string, _ http.Handler) {
	r.Deletes = append(r.Deletes, path)
}

// HasGets ensures all gets routes are present
func (r *Router) HasGets(gets ...string) error {
	return r.hasRoutes(gets, r.Gets)
}

// HasPosts ensures all gets routes are present
func (r *Router) HasPosts(posts ...string) error {
	return r.hasRoutes(posts, r.Posts)
}

// HasDeletes ensures all gets routes are present
func (r *Router) HasDeletes(deletes ...string) error {
	return r.hasRoutes(deletes, r.Deletes)
}

func (r *Router) hasRoutes(want []string, got []string) error {
	if len(got) != len(want) {
		return errors.Errorf("want: %d get routes, got: %d", len(want), len(got))
	}

	for i, w := range want {
		g := got[i]
		if w != g {
			return errors.Errorf("wanted route: %s [%d], but got: %s", w, i, g)
		}
	}

	return nil
}

// ErrorHandler just holds the last error
type ErrorHandler struct {
	Error error
}

// Wrap an http method
func (e *ErrorHandler) Wrap(handler func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := handler(w, r); err != nil {
			e.Error = err
		}
	})
}
