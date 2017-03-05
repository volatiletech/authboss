package authboss

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

type mockClientStateReadWriter struct {
	state mockClientState
}

type mockClientState map[string]string

func newMockClientStateRW(keyValue ...string) mockClientStateReadWriter {
	state := mockClientState{}
	for i := 0; i < len(keyValue); i += 2 {
		key, value := keyValue[i], keyValue[i+1]
		state[key] = value
	}

	return mockClientStateReadWriter{state}
}

func (m mockClientStateReadWriter) ReadState(w http.ResponseWriter, r *http.Request) (ClientState, error) {
	return m.state, nil
}

func (m mockClientStateReadWriter) WriteState(w http.ResponseWriter, cs ClientState, evs []ClientStateEvent) error {
	var state mockClientState

	if cs != nil {
		state = cs.(mockClientState)
	} else {
		state = mockClientState{}
	}

	for _, ev := range evs {
		switch ev.Kind {
		case ClientStateEventPut:
			state[ev.Key] = ev.Value
		case ClientStateEventDel:
			delete(state, ev.Key)
		}
	}

	b, err := json.Marshal(state)
	if err != nil {
		return err
	}

	w.Header().Set("test_session", string(b))
	return nil
}

func (m mockClientState) Get(key string) (string, bool) {
	val, ok := m[key]
	return val, ok
}

func newMockRequest(postKeyValues ...string) *http.Request {
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

func newMockAPIRequest(postKeyValues ...string) *http.Request {
	kv := map[string]string{}
	for i := 0; i < len(postKeyValues); i += 2 {
		key, value := postKeyValues[i], postKeyValues[i+1]
		kv[key] = value
	}

	b, err := json.Marshal(kv)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", "http://localhost", bytes.NewReader(b))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

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

type mockRenderLoader struct{}

func (m mockRenderLoader) Init(names []string) (Renderer, error) {
	return mockRenderer{}, nil
}

type mockRenderer struct {
	expectName string
}

func (m mockRenderer) Render(ctx context.Context, name string, data HTMLData) ([]byte, string, error) {
	if len(m.expectName) != 0 && m.expectName != name {
		panic(fmt.Sprintf("want template name: %s, but got: %s", m.expectName, name))
	}

	b, err := json.Marshal(data)
	return b, "application/json", err
}

type mockEmailRenderer struct{}

func (m mockEmailRenderer) Render(ctx context.Context, name string, data HTMLData) ([]byte, string, error) {
	switch name {
	case "text":
		return []byte("a development text e-mail template"), "text/plain", nil
	case "html":
		return []byte("a development html e-mail template"), "text/html", nil
	default:
		panic("shouldn't get here")
	}
}
