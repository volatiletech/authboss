// Package mocks defines implemented interfaces for testing modules
package mocks

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/authboss.v1"
)

// MockUser represents all possible fields a authboss User may have
type MockUser struct {
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
	OauthToken         string
	OauthRefresh       string
	OauthExpiry        time.Time
}

// MockStorer should be valid for any module storer defined in authboss.
type MockStorer struct {
	Users          map[string]authboss.Attributes
	Tokens         map[string][]string
	CreateErr      string
	PutErr         string
	GetErr         string
	AddTokenErr    string
	DelTokensErr   string
	UseTokenErr    string
	RecoverUserErr string
	ConfirmUserErr string
}

// NewMockStorer constructor
func NewMockStorer() *MockStorer {
	return &MockStorer{
		Users:  make(map[string]authboss.Attributes),
		Tokens: make(map[string][]string),
	}
}

// Create a new user
func (m *MockStorer) Create(key string, attr authboss.Attributes) error {
	if len(m.CreateErr) > 0 {
		return errors.New(m.CreateErr)
	}

	m.Users[key] = attr
	return nil
}

// Put updates to a user
func (m *MockStorer) Put(key string, attr authboss.Attributes) error {
	if len(m.PutErr) > 0 {
		return errors.New(m.PutErr)
	}

	if _, ok := m.Users[key]; !ok {
		m.Users[key] = attr
		return nil
	}
	for k, v := range attr {
		m.Users[key][k] = v
	}
	return nil
}

// Get a user
func (m *MockStorer) Get(key string) (result interface{}, err error) {
	if len(m.GetErr) > 0 {
		return nil, errors.New(m.GetErr)
	}

	userAttrs, ok := m.Users[key]
	if !ok {
		return nil, authboss.ErrUserNotFound
	}

	u := &MockUser{}
	if err := userAttrs.Bind(u, true); err != nil {
		panic(err)
	}

	return u, nil
}

// PutOAuth user
func (m *MockStorer) PutOAuth(uid, provider string, attr authboss.Attributes) error {
	if len(m.PutErr) > 0 {
		return errors.New(m.PutErr)
	}

	if _, ok := m.Users[uid+provider]; !ok {
		m.Users[uid+provider] = attr
		return nil
	}
	for k, v := range attr {
		m.Users[uid+provider][k] = v
	}
	return nil
}

// GetOAuth user
func (m *MockStorer) GetOAuth(uid, provider string) (result interface{}, err error) {
	if len(m.GetErr) > 0 {
		return nil, errors.New(m.GetErr)
	}

	userAttrs, ok := m.Users[uid+provider]
	if !ok {
		return nil, authboss.ErrUserNotFound
	}

	u := &MockUser{}
	if err := userAttrs.Bind(u, true); err != nil {
		panic(err)
	}

	return u, nil
}

// AddToken for remember me
func (m *MockStorer) AddToken(key, token string) error {
	if len(m.AddTokenErr) > 0 {
		return errors.New(m.AddTokenErr)
	}

	arr := m.Tokens[key]
	m.Tokens[key] = append(arr, token)
	return nil
}

// DelTokens for a user
func (m *MockStorer) DelTokens(key string) error {
	if len(m.DelTokensErr) > 0 {
		return errors.New(m.DelTokensErr)
	}

	delete(m.Tokens, key)
	return nil
}

// UseToken if it exists, deleting it in the process
func (m *MockStorer) UseToken(givenKey, token string) (err error) {
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
func (m *MockStorer) RecoverUser(token string) (result interface{}, err error) {
	if len(m.RecoverUserErr) > 0 {
		return nil, errors.New(m.RecoverUserErr)
	}

	for _, user := range m.Users {
		if user["recover_token"] == token {

			u := &MockUser{}
			if err = user.Bind(u, false); err != nil {
				panic(err)
			}

			return u, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// ConfirmUser via their token
func (m *MockStorer) ConfirmUser(confirmToken string) (result interface{}, err error) {
	if len(m.ConfirmUserErr) > 0 {
		return nil, errors.New(m.ConfirmUserErr)
	}

	for _, user := range m.Users {
		if user["confirm_token"] == confirmToken {

			u := &MockUser{}
			if err = user.Bind(u, false); err != nil {
				panic(err)
			}

			return u, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// MockFailStorer is used for testing module initialize functions that recover more than the base storer
type MockFailStorer struct{}

// Create fails
func (_ MockFailStorer) Create(_ string, _ authboss.Attributes) error {
	return errors.New("fail storer: create")
}

// Put fails
func (_ MockFailStorer) Put(_ string, _ authboss.Attributes) error {
	return errors.New("fail storer: put")
}

// Get fails
func (_ MockFailStorer) Get(_ string) (interface{}, error) {
	return nil, errors.New("fail storer: get")
}

// MockClientStorer is used for testing the client stores on context
type MockClientStorer struct {
	Values        map[string]string
	GetShouldFail bool
}

// NewMockClientStorer constructs a MockClientStorer
func NewMockClientStorer(data ...string) *MockClientStorer {
	if len(data)%2 != 0 {
		panic("It should be a key value list of arguments.")
	}

	values := make(map[string]string)

	for i := 0; i < len(data)-1; i += 2 {
		values[data[i]] = data[i+1]
	}

	return &MockClientStorer{Values: values}
}

// Get a key's value
func (m *MockClientStorer) Get(key string) (string, bool) {
	if m.GetShouldFail {
		return "", false
	}

	v, ok := m.Values[key]
	return v, ok
}

// GetErr gets a key's value or err if not exist
func (m *MockClientStorer) GetErr(key string) (string, error) {
	if m.GetShouldFail {
		return "", authboss.ClientDataErr{Name: key}
	}

	v, ok := m.Values[key]
	if !ok {
		return v, authboss.ClientDataErr{Name: key}
	}
	return v, nil
}

// Put a value
func (m *MockClientStorer) Put(key, val string) { m.Values[key] = val }

// Del a key/value pair
func (m *MockClientStorer) Del(key string) { delete(m.Values, key) }

// MockRequest returns a new mock request with optional key-value body (form-post)
func MockRequest(method string, postKeyValues ...string) *http.Request {
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

// MockMailer helps simplify mailer testing by storing the last sent email
type MockMailer struct {
	Last    authboss.Email
	SendErr string
}

// NewMockMailer constructs a mock mailer
func NewMockMailer() *MockMailer {
	return &MockMailer{}
}

// Send an e-mail
func (m *MockMailer) Send(email authboss.Email) error {
	if len(m.SendErr) > 0 {
		return errors.New(m.SendErr)
	}

	m.Last = email
	return nil
}

// MockAfterCallback is a callback that knows if it was called
type MockAfterCallback struct {
	HasBeenCalled bool
	Fn            authboss.After
}

// NewMockAfterCallback constructs a new mockaftercallback.
func NewMockAfterCallback() *MockAfterCallback {
	m := MockAfterCallback{}

	m.Fn = func(_ *authboss.Context) error {
		m.HasBeenCalled = true
		return nil
	}

	return &m
}
