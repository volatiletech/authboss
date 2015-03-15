package authboss

import (
	"bytes"
	"fmt"
	"net/http"
)

type mockUser struct {
	Email    string
	Password string
}

type mockStorer map[string]Attributes

func (m mockStorer) Create(key string, attr Attributes) error {
	m[key] = attr
	return nil
}

func (m mockStorer) Put(key string, attr Attributes) error {
	m[key] = attr
	return nil
}

func (m mockStorer) Get(key string) (result interface{}, err error) {
	return &mockUser{
		m[key]["email"].(string), m[key]["password"].(string),
	}, nil
}

func (m mockStorer) PutOAuth(uid, provider string, attr Attributes) error {
	m[uid+provider] = attr
	return nil
}

func (m mockStorer) GetOAuth(uid, provider string) (result interface{}, err error) {
	return &mockUser{
		m[uid+provider]["email"].(string), m[uid+provider]["password"].(string),
	}, nil
}

type mockClientStore map[string]string

func (m mockClientStore) Get(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}
func (m mockClientStore) GetErr(key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return v, ClientDataErr{key}
	}
	return v, nil
}
func (m mockClientStore) Put(key, val string) { m[key] = val }
func (m mockClientStore) Del(key string)      { delete(m, key) }

func mockRequestContext(postKeyValues ...string) *Context {
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

	ctx, err := ContextFromRequest(req)
	if err != nil {
		panic(err)
	}

	return ctx
}

type mockValidator struct {
	FieldName string
	Errs      ErrorList
	Ruleset   []string
}

func (m mockValidator) Field() string {
	return m.FieldName
}

func (m mockValidator) Errors(in string) ErrorList {
	return m.Errs
}

func (m mockValidator) Rules() []string {
	return m.Ruleset
}
