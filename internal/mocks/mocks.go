package mocks

import (
	"bytes"
	"fmt"
	"net/http"

	"gopkg.in/authboss.v0"
)

type MockUser struct {
	Username string
	Email    string
	Password string
}

type MockStorer struct {
	Users  map[string]authboss.Attributes
	Tokens map[string][]string
}

func NewMockStorer() *MockStorer {
	return &MockStorer{
		Users:  make(map[string]authboss.Attributes),
		Tokens: make(map[string][]string),
	}
}

func (m *MockStorer) Create(key string, attr authboss.Attributes) error {
	m.Users[key] = attr
	return nil
}

func (m *MockStorer) Put(key string, attr authboss.Attributes) error {
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
	if _, ok := m.Users[key]; !ok {
		return nil, authboss.ErrUserNotFound
	}

	u := &MockUser{}

	if val, ok := m.Users[key]["username"]; ok {
		u.Username = val.(string)
	}

	if val, ok := m.Users[key]["email"]; ok {
		u.Email = val.(string)
	}

	if val, ok := m.Users[key]["password"]; ok {
		u.Password = val.(string)
	}

	return u, nil
}

func (m *MockStorer) AddToken(key, token string) error {
	arr := m.Tokens[key]
	m.Tokens[key] = append(arr, token)
	return nil
}

func (m *MockStorer) DelTokens(key string) error {
	delete(m.Tokens, key)
	return nil
}

func (m *MockStorer) UseToken(givenKey, token string) (key string, err error) {
	if arr, ok := m.Tokens[givenKey]; ok {
		for _, tok := range arr {
			if tok == token {
				return givenKey, nil
			}
		}
	}

	return "", authboss.ErrTokenNotFound
}

func (m *MockStorer) RecoverUser(token string) (interface{}, error) {
	return nil, nil
}

type MockClientStorer map[string]string

func (m MockClientStorer) Get(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}
func (m MockClientStorer) Put(key, val string) { m[key] = val }
func (m MockClientStorer) Del(key string)      { delete(m, key) }

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

type MockMailer struct {
	Last authboss.Email
}

func (m *MockMailer) Send(email authboss.Email) error {
	m.Last = email
	return nil
}
