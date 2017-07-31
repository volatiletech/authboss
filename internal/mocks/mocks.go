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
	OAuthToken         string
	OAuthRefresh       string
	OAuthExpiry        time.Time
}

func (m MockUser) GetUsername(context.Context) (string, error)     { return m.Username, nil }
func (m MockUser) GetEmail(context.Context) (string, error)        { return m.Email, nil }
func (m MockUser) GetPassword(context.Context) (string, error)     { return m.Password, nil }
func (m MockUser) GetRecoverToken(context.Context) (string, error) { return m.RecoverToken, nil }
func (m MockUser) GetRecoverTokenExpiry(context.Context) (time.Time, error) {
	return m.RecoverTokenExpiry, nil
}
func (m MockUser) GetConfirmToken(context.Context) (string, error) { return m.ConfirmToken, nil }
func (m MockUser) GetConfirmed(context.Context) (bool, error)      { return m.Confirmed, nil }
func (m MockUser) GetLocked(context.Context) (bool, error)         { return m.Locked, nil }
func (m MockUser) GetAttemptNumber(context.Context) (int, error)   { return m.AttemptNumber, nil }
func (m MockUser) GetAttemptTime(context.Context) (time.Time, error) {
	return m.AttemptTime, nil
}
func (m MockUser) GetOAuthToken(context.Context) (string, error)   { return m.OAuthToken, nil }
func (m MockUser) GetOAuthRefresh(context.Context) (string, error) { return m.OAuthRefresh, nil }
func (m MockUser) GetOAuthExpiry(context.Context) (time.Time, error) {
	return m.OAuthExpiry, nil
}

func (m *MockUser) SetUsername(ctx context.Context, username string) error {
	m.Username = username
	return nil
}
func (m *MockUser) SetEmail(ctx context.Context, email string) error {
	m.Email = email
	return nil
}
func (m *MockUser) SetPassword(ctx context.Context, password string) error {
	m.Password = password
	return nil
}
func (m *MockUser) SetRecoverToken(ctx context.Context, recoverToken string) error {
	m.RecoverToken = recoverToken
	return nil
}
func (m *MockUser) SetRecoverTokenExpiry(ctx context.Context, recoverTokenExpiry time.Time) error {
	m.RecoverTokenExpiry = recoverTokenExpiry
	return nil
}
func (m *MockUser) SetConfirmToken(ctx context.Context, confirmToken string) error {
	m.ConfirmToken = confirmToken
	return nil
}
func (m *MockUser) SetConfirmed(ctx context.Context, confirmed bool) error {
	m.Confirmed = confirmed
	return nil
}
func (m *MockUser) SetLocked(ctx context.Context, locked bool) error {
	m.Locked = locked
	return nil
}
func (m *MockUser) SetAttemptNumber(ctx context.Context, attemptNumber int) error {
	m.AttemptNumber = attemptNumber
	return nil
}
func (m *MockUser) SetAttemptTime(ctx context.Context, attemptTime time.Time) error {
	m.AttemptTime = attemptTime
	return nil
}
func (m *MockUser) SetOAuthToken(ctx context.Context, oAuthToken string) error {
	m.OAuthToken = oAuthToken
	return nil
}
func (m *MockUser) SetOAuthRefresh(ctx context.Context, oAuthRefresh string) error {
	m.OAuthRefresh = oAuthRefresh
	return nil
}
func (m *MockUser) SetOAuthExpiry(ctx context.Context, oAuthExpiry time.Time) error {
	m.OAuthExpiry = oAuthExpiry
	return nil
}

// MockStorer should be valid for any module storer defined in authboss.
type MockStoreLoader struct {
	Users    map[string]*MockUser
	RMTokens map[string][]string
}

// NewMockStorer constructor
func NewMockStoreLoader() *MockStoreLoader {
	return &MockStoreLoader{
		Users:    make(map[string]*MockUser),
		RMTokens: make(map[string][]string),
	}
}

/*
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
*/

// MockFailStorer is used for testing module initialize functions that recover more than the base storer
type MockFailStorer struct {
	MockUser
}

// Create fails
func (_ MockFailStorer) Create(context.Context) error {
	return errors.New("fail storer: create")
}

// Put fails
func (_ MockFailStorer) Save(context.Context) error {
	return errors.New("fail storer: put")
}

// Get fails
func (_ MockFailStorer) Load(context.Context) error {
	return errors.New("fail storer: get")
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
func (m *MockMailer) Send(ctx context.Context, email authboss.Email) error {
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

	m.Fn = func(context.Context) error {
		m.HasBeenCalled = true
		return nil
	}

	return &m
}
