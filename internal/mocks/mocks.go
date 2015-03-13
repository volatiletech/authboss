// mocks defines implemented interfaces for testing modules
package mocks

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"

	"gopkg.in/authboss.v0"
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

func NewMockStorer() *MockStorer {
	return &MockStorer{
		Users:  make(map[string]authboss.Attributes),
		Tokens: make(map[string][]string),
	}
}

func (m *MockStorer) Create(key string, attr authboss.Attributes) error {
	if len(m.CreateErr) > 0 {
		return errors.New(m.CreateErr)
	}

	m.Users[key] = attr
	return nil
}

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

func (m *MockStorer) Get(key string, attrMeta authboss.AttributeMeta) (result interface{}, err error) {
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

func (m *MockStorer) AddToken(key, token string) error {
	if len(m.AddTokenErr) > 0 {
		return errors.New(m.AddTokenErr)
	}

	arr := m.Tokens[key]
	m.Tokens[key] = append(arr, token)
	return nil
}

func (m *MockStorer) DelTokens(key string) error {
	if len(m.DelTokensErr) > 0 {
		return errors.New(m.DelTokensErr)
	}

	delete(m.Tokens, key)
	return nil
}

func (m *MockStorer) UseToken(givenKey, token string) (key string, err error) {
	if len(m.UseTokenErr) > 0 {
		return "", errors.New(m.UseTokenErr)
	}

	if arr, ok := m.Tokens[givenKey]; ok {
		for _, tok := range arr {
			if tok == token {
				return givenKey, nil
			}
		}
	}

	return "", authboss.ErrTokenNotFound
}

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

func (m *MockStorer) OAuth2NewOrUpdate(key string, attr authboss.Attributes) error {
	if len(m.CreateErr) > 0 {
		return errors.New(m.CreateErr)
	}

	m.Users[key] = attr
	return nil
}

// MockFailStorer is used for testing module initialize functions that recover more than the base storer
type MockFailStorer struct{}

func (_ MockFailStorer) Create(_ string, _ authboss.Attributes) error {
	return errors.New("fail storer: create")
}
func (_ MockFailStorer) Put(_ string, _ authboss.Attributes) error {
	return errors.New("fail storer: put")
}
func (_ MockFailStorer) Get(_ string, _ authboss.AttributeMeta) (interface{}, error) {
	return nil, errors.New("fail storer: get")
}

// MockClientStorer is used for testing the client stores on context
type MockClientStorer struct {
	Values        map[string]string
	GetShouldFail bool
}

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

func (m *MockClientStorer) Get(key string) (string, bool) {
	if m.GetShouldFail {
		return "", false
	}

	v, ok := m.Values[key]
	return v, ok
}
func (m *MockClientStorer) GetErr(key string) (string, error) {
	if m.GetShouldFail {
		return "", authboss.ClientDataErr{key}
	}

	v, ok := m.Values[key]
	if !ok {
		return v, authboss.ClientDataErr{key}
	}
	return v, nil
}
func (m *MockClientStorer) Put(key, val string) { m.Values[key] = val }
func (m *MockClientStorer) Del(key string)      { delete(m.Values, key) }

// MockRequestContext returns a new context as if it came from POST request.
func MockRequestContext(postKeyValues ...string) *authboss.Context {
	keyValues := &bytes.Buffer{}
	for i := 0; i < len(postKeyValues); i += 2 {
		if i != 0 {
			keyValues.WriteByte('&')
		}
		fmt.Fprintf(keyValues, "%s=%s", postKeyValues[i], postKeyValues[i+1])
	}

	req, err := http.NewRequest("POST", "http://localhost", keyValues)
	if err != nil {
		panic(err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx, err := authboss.ContextFromRequest(req)
	if err != nil {
		panic(err)
	}

	return ctx
}

// MockMailer helps simplify mailer testing by storing the last sent email
type MockMailer struct {
	Last    authboss.Email
	SendErr string
}

func NewMockMailer() *MockMailer {
	return &MockMailer{}
}

func (m *MockMailer) Send(email authboss.Email) error {
	if len(m.SendErr) > 0 {
		return errors.New(m.SendErr)
	}

	m.Last = email
	return nil
}

type MockAfterCallback struct {
	HasBeenCalled bool
	Fn            authboss.After
}

func NewMockAfterCallback() *MockAfterCallback {
	m := MockAfterCallback{}

	m.Fn = func(_ *authboss.Context) error {
		m.HasBeenCalled = true
		return nil
	}

	return &m
}
