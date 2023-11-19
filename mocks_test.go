package authboss

import (
	"context"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type mockUser struct {
	Email    string
	Password string
	Username string

	RecoverSelector string
	RecoverVerifier string
	RecoverExpiry   time.Time

	ConfirmSelector string
	ConfirmVerifier string
	Confirmed       bool

	AttemptCount int
	LastAttempt  time.Time
	Locked       time.Time

	OAuth2UID      string
	OAuth2Provider string
	OAuth2Token    string
	OAuth2Refresh  string
	OAuth2Expiry   time.Time

	Arbitrary map[string]string
}

func newMockServerStorer() *mockServerStorer {
	return &mockServerStorer{
		Users:  make(map[string]*mockUser),
		Tokens: make(map[string][]string),
	}
}

type mockServerStorer struct {
	Users  map[string]*mockUser
	Tokens map[string][]string
}

func (m *mockServerStorer) Load(ctx context.Context, key string) (User, error) {
	u, ok := m.Users[key]
	if !ok {
		return nil, ErrUserNotFound
	}

	return u, nil
}

func (m *mockServerStorer) Save(ctx context.Context, user User) error {
	u := user.(*mockUser)
	m.Users[u.Email] = u

	return nil
}

func (m *mockServerStorer) AddRememberToken(ctx context.Context, pid, token string) error {
	m.Tokens[pid] = append(m.Tokens[pid], token)
	return nil
}

func (m *mockServerStorer) DelRememberTokens(ctx context.Context, pid string) error {
	delete(m.Tokens, pid)
	return nil
}

func (m *mockServerStorer) UseRememberToken(ctx context.Context, pid, token string) error {
	arr, ok := m.Tokens[pid]
	if !ok {
		return ErrTokenNotFound
	}

	for i, tok := range arr {
		if tok == token {
			arr[i] = arr[len(arr)-1]
			m.Tokens[pid] = arr[:len(arr)-2]
			return nil
		}
	}

	return ErrTokenNotFound
}

// This section of functions was purely for test coverage
func (m *mockServerStorer) New(ctx context.Context) User                { panic("not impl") }
func (m *mockServerStorer) Create(ctx context.Context, user User) error { panic("not impl") }
func (m *mockServerStorer) NewFromOAuth2(ctx context.Context, provider string, details map[string]string) (OAuth2User, error) {
	panic("not impl")
}
func (m *mockServerStorer) LoadByConfirmSelector(ctx context.Context, selector string) (ConfirmableUser, error) {
	panic("not impl")
}
func (m *mockServerStorer) LoadByRecoverSelector(ctx context.Context, selector string) (RecoverableUser, error) {
	panic("not impl")
}
func (m *mockServerStorer) SaveOAuth2(ctx context.Context, user OAuth2User) error { panic("not impl") }

func (m mockUser) GetPID() string                             { return m.Email }
func (m mockUser) GetEmail() string                           { return m.Email }
func (m mockUser) GetUsername() string                        { return m.Username }
func (m mockUser) GetPassword() string                        { return m.Password }
func (m mockUser) GetRecoverSelector() string                 { return m.RecoverSelector }
func (m mockUser) GetRecoverVerifier() string                 { return m.RecoverVerifier }
func (m mockUser) GetRecoverExpiry() time.Time                { return m.RecoverExpiry }
func (m mockUser) GetConfirmSelector() string                 { return m.ConfirmSelector }
func (m mockUser) GetConfirmVerifier() string                 { return m.ConfirmVerifier }
func (m mockUser) GetConfirmed() bool                         { return m.Confirmed }
func (m mockUser) GetAttemptCount() int                       { return m.AttemptCount }
func (m mockUser) GetLastAttempt() time.Time                  { return m.LastAttempt }
func (m mockUser) GetLocked() time.Time                       { return m.Locked }
func (m mockUser) IsOAuth2User() bool                         { return len(m.OAuth2Provider) != 0 }
func (m mockUser) GetOAuth2UID() string                       { return m.OAuth2UID }
func (m mockUser) GetOAuth2Provider() string                  { return m.OAuth2Provider }
func (m mockUser) GetOAuth2AccessToken() string               { return m.OAuth2Token }
func (m mockUser) GetOAuth2RefreshToken() string              { return m.OAuth2Refresh }
func (m mockUser) GetOAuth2Expiry() time.Time                 { return m.OAuth2Expiry }
func (m mockUser) GetArbitrary() map[string]string            { return m.Arbitrary }
func (m *mockUser) PutPID(email string)                       { m.Email = email }
func (m *mockUser) PutUsername(username string)               { m.Username = username }
func (m *mockUser) PutEmail(email string)                     { m.Email = email }
func (m *mockUser) PutPassword(password string)               { m.Password = password }
func (m *mockUser) PutRecoverSelector(recoverSelector string) { m.RecoverSelector = recoverSelector }
func (m *mockUser) PutRecoverVerifier(recoverVerifier string) { m.RecoverVerifier = recoverVerifier }
func (m *mockUser) PutRecoverExpiry(recoverExpiry time.Time)  { m.RecoverExpiry = recoverExpiry }
func (m *mockUser) PutConfirmSelector(confirmSelector string) { m.ConfirmSelector = confirmSelector }
func (m *mockUser) PutConfirmVerifier(confirmVerifier string) { m.ConfirmVerifier = confirmVerifier }
func (m *mockUser) PutConfirmed(confirmed bool)               { m.Confirmed = confirmed }
func (m *mockUser) PutAttemptCount(attemptCount int)          { m.AttemptCount = attemptCount }
func (m *mockUser) PutLastAttempt(attemptTime time.Time)      { m.LastAttempt = attemptTime }
func (m *mockUser) PutLocked(locked time.Time)                { m.Locked = locked }
func (m *mockUser) PutOAuth2UID(uid string)                   { m.OAuth2UID = uid }
func (m *mockUser) PutOAuth2Provider(provider string)         { m.OAuth2Provider = provider }
func (m *mockUser) PutOAuth2AccessToken(token string)         { m.OAuth2Token = token }
func (m *mockUser) PutOAuth2RefreshToken(refresh string)      { m.OAuth2Refresh = refresh }
func (m *mockUser) PutOAuth2Expiry(expiry time.Time)          { m.OAuth2Expiry = expiry }
func (m *mockUser) PutArbitrary(arb map[string]string)        { m.Arbitrary = arb }

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

func (m mockClientStateReadWriter) ReadState(r *http.Request) (ClientState, error) {
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

type mockEmailRenderer struct{}

func (m mockEmailRenderer) Load(names ...string) error { return nil }

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

type mockLogger struct{}

func (m mockLogger) Info(s string)  {}
func (m mockLogger) Error(s string) {}

type mockHasher struct{}

func (m mockHasher) GenerateHash(s string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (m mockHasher) CompareHashAndPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
