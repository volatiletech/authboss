package auth

import (
	"errors"

	"strings"

	"gopkg.in/authboss.v0"
)

type MockUser struct {
	Username, Password string
}

type MockUserStorer struct {
	Users []MockUser
}

func NewMockUserStorer() *MockUserStorer {
	return &MockUserStorer{
		Users: []MockUser{
			{"John", "$2a$10$0hwgO.5fThx0DOHbErIxaemMTrU3RDNJchM6ToMOmFf.hkuX4RKRK"}, // 1234
			{"Jane", "$2a$10$tzIH0BU8BpOOsf768Iv4KecouL0gPgrvCpYZpBwJozlqezfabBpr2"}, // asdf
		},
	}
}

func (s MockUserStorer) Create(key string, attr authboss.Attributes) error {
	return errors.New("Not implemented")
}

func (s MockUserStorer) Put(key string, attr authboss.Attributes) error {
	return errors.New("Not implemented")
}

func (s MockUserStorer) Get(key string, attrMeta authboss.AttributeMeta) (result interface{}, err error) {
	for _, u := range s.Users {
		if strings.EqualFold(u.Username, key) {
			return u, nil
		}
	}

	return nil, errors.New("User not found")
}

type testClientStorer map[string]string

func (t testClientStorer) Put(key, value string) {
	t[key] = value
}

func (t testClientStorer) Get(key string) (string, bool) {
	s, ok := t[key]
	return s, ok
}

func (t testClientStorer) Del(key string) {
	delete(t, key)
}
