package authboss

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type mockUser struct {
	Email    string
	Password string
}

type mockStoredUser struct {
	mockUser
	mockStoreLoader
}

type mockStoreLoader map[string]mockUser

func (m mockStoreLoader) Load(ctx context.Context, key string) (Storer, error) {
	u, ok := m[key]
	if !ok {
		return nil, ErrUserNotFound
	}

	return mockStoredUser{
		mockUser:        u,
		mockStoreLoader: m,
	}, nil
}

func (m mockStoredUser) Load(ctx context.Context) error {
	u, ok := m.mockStoreLoader[m.Email]
	if !ok {
		return ErrUserNotFound
	}

	m.Email = u.Email
	m.Password = u.Password

	return nil
}

func (m mockStoredUser) Save(ctx context.Context) error {
	m.mockStoreLoader[m.Email] = m.mockUser

	return nil
}

func (m mockStoredUser) PutEmail(ctx context.Context, email string) error {
	m.Email = email
	return nil
}

func (m mockStoredUser) PutUsername(ctx context.Context, username string) error {
	return errors.New("not impl")
}

func (m mockStoredUser) PutPassword(ctx context.Context, password string) error {
	m.Password = password
	return nil
}

func (m mockStoredUser) GetEmail(ctx context.Context) (email string, err error) {
	return m.Email, nil
}

func (m mockStoredUser) GetUsername(ctx context.Context) (username string, err error) {
	return "", errors.New("not impl")
}

func (m mockStoredUser) GetPassword(ctx context.Context) (password string, err error) {
	return m.Password, nil
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

func mockRequest(postKeyValues ...string) *http.Request {
	urlValues := make(url.Values)
	for i := 0; i < len(postKeyValues); i += 2 {
		urlValues.Set(postKeyValues[i], postKeyValues[i+1])
	}

	req, err := http.NewRequest("POST", "http://localhost", strings.NewReader(urlValues.Encode()))
	if err != nil {
		panic(err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
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
