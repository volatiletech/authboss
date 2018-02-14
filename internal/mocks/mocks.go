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
	Locked             bool
	AttemptNumber      int
	AttemptTime        time.Time
	OAuthToken         string
	OAuthRefresh       string
	OAuthExpiry        time.Time
}

func (m User) GetUsername(context.Context) (string, error)     { return m.Username, nil }
func (m User) GetPID(context.Context) (string, error)          { return m.Email, nil }
func (m User) GetPassword(context.Context) (string, error)     { return m.Password, nil }
func (m User) GetRecoverToken(context.Context) (string, error) { return m.RecoverToken, nil }
func (m User) GetRecoverTokenExpiry(context.Context) (time.Time, error) {
	return m.RecoverTokenExpiry, nil
}
func (m User) GetConfirmToken(context.Context) (string, error) { return m.ConfirmToken, nil }
func (m User) GetConfirmed(context.Context) (bool, error)      { return m.Confirmed, nil }
func (m User) GetLocked(context.Context) (bool, error)         { return m.Locked, nil }
func (m User) GetAttemptNumber(context.Context) (int, error)   { return m.AttemptNumber, nil }
func (m User) GetAttemptTime(context.Context) (time.Time, error) {
	return m.AttemptTime, nil
}
func (m User) GetOAuthToken(context.Context) (string, error)   { return m.OAuthToken, nil }
func (m User) GetOAuthRefresh(context.Context) (string, error) { return m.OAuthRefresh, nil }
func (m User) GetOAuthExpiry(context.Context) (time.Time, error) {
	return m.OAuthExpiry, nil
}

func (m *User) SetUsername(ctx context.Context, username string) error {
	m.Username = username
	return nil
}
func (m *User) SetEmail(ctx context.Context, email string) error {
	m.Email = email
	return nil
}
func (m *User) SetPassword(ctx context.Context, password string) error {
	m.Password = password
	return nil
}
func (m *User) SetRecoverToken(ctx context.Context, recoverToken string) error {
	m.RecoverToken = recoverToken
	return nil
}
func (m *User) SetRecoverTokenExpiry(ctx context.Context, recoverTokenExpiry time.Time) error {
	m.RecoverTokenExpiry = recoverTokenExpiry
	return nil
}
func (m *User) SetConfirmToken(ctx context.Context, confirmToken string) error {
	m.ConfirmToken = confirmToken
	return nil
}
func (m *User) SetConfirmed(ctx context.Context, confirmed bool) error {
	m.Confirmed = confirmed
	return nil
}
func (m *User) SetLocked(ctx context.Context, locked bool) error {
	m.Locked = locked
	return nil
}
func (m *User) SetAttemptNumber(ctx context.Context, attemptNumber int) error {
	m.AttemptNumber = attemptNumber
	return nil
}
func (m *User) SetAttemptTime(ctx context.Context, attemptTime time.Time) error {
	m.AttemptTime = attemptTime
	return nil
}
func (m *User) SetOAuthToken(ctx context.Context, oAuthToken string) error {
	m.OAuthToken = oAuthToken
	return nil
}
func (m *User) SetOAuthRefresh(ctx context.Context, oAuthRefresh string) error {
	m.OAuthRefresh = oAuthRefresh
	return nil
}
func (m *User) SetOAuthExpiry(ctx context.Context, oAuthExpiry time.Time) error {
	m.OAuthExpiry = oAuthExpiry
	return nil
}

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

/*
// TODO(aarondl): What is this?
// AddToken for remember me
func (m *Storer) AddToken(key, token string) error {
	if len(m.AddTokenErr) > 0 {
		return errors.New(m.AddTokenErr)
	}

	arr := m.Tokens[key]
	m.Tokens[key] = append(arr, token)
	return nil
}

// DelTokens for a user
func (m *Storer) DelTokens(key string) error {
	if len(m.DelTokensErr) > 0 {
		return errors.New(m.DelTokensErr)
	}

	delete(m.Tokens, key)
	return nil
}

// UseToken if it exists, deleting it in the process
func (m *Storer) UseToken(givenKey, token string) (err error) {
	if len(m.UseTokenErr) > 0 {
		return errors.New(m.UseTokenErr)
	}

	if arr, ok := m.Tokens[givenKey]; ok {
		for _, tok := range arr {
			if tok == token {
				return nil
			}
		}
	}

	return authboss.ErrTokenNotFound
}

// RecoverUser by the token.
func (m *Storer) RecoverUser(token string) (result interface{}, err error) {
	if len(m.RecoverUserErr) > 0 {
		return nil, errors.New(m.RecoverUserErr)
	}

	for _, user := range m.Users {
		if user["recover_token"] == token {

			u := &User{}
			if err = user.Bind(u, false); err != nil {
				panic(err)
			}

			return u, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// ConfirmUser via their token
func (m *Storer) ConfirmUser(confirmToken string) (result interface{}, err error) {
	if len(m.ConfirmUserErr) > 0 {
		return nil, errors.New(m.ConfirmUserErr)
	}

	for _, user := range m.Users {
		if user["confirm_token"] == confirmToken {

			u := &User{}
			if err = user.Bind(u, false); err != nil {
				panic(err)
			}

			return u, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}
*/

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

// ClientRW is used for testing the client stores on context
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
func (c *ClientStateRW) ReadState(http.ResponseWriter, *http.Request) (authboss.ClientState, error) {
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

// Request returns a new  request with optional key-value body (form-post)
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
	Fn            authboss.After
}

// NewAfterCallback constructs a new aftercallback.
func NewAfterCallback() *AfterCallback {
	m := AfterCallback{}

	m.Fn = func(context.Context) error {
		m.HasBeenCalled = true
		return nil
	}

	return &m
}
