package authboss

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type mockUser struct {
	Email    string
	Password string
}

type mockServerStorer map[string]mockUser

func (m mockServerStorer) Load(ctx context.Context, key string) (User, error) {
	u, ok := m[key]
	if !ok {
		return nil, ErrUserNotFound
	}

	return u, nil
}

func (m mockServerStorer) Save(ctx context.Context, user User) error {
	pid := user.GetPID(ctx)
	m[pid] = user.(mockUser)

	return nil
}

func (m mockUser) PutPID(ctx context.Context, email string) {
	m.Email = email
}

func (m mockUser) PutPassword(ctx context.Context, password string) {
	m.Password = password
}

func (m mockUser) GetPID(ctx context.Context) (email string) {
	return m.Email
}

func (m mockUser) GetPassword(ctx context.Context) (password string) {
	return m.Password
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

type mockRenderer struct {
	expectName string
}

func (m mockRenderer) Load(names ...string) error {
	return nil
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
