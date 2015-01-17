package authboss

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

func (m mockStorer) Get(key string, attrMeta AttributeMeta) (result interface{}, err error) {
	return &mockUser{
		m[key]["email"].(string), m[key]["password"].(string),
	}, nil
}

type mockClientStore map[string]string

func (m mockClientStore) Get(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}
func (m mockClientStore) Put(key, val string) { m[key] = val }
func (m mockClientStore) Del(key string)      { delete(m, key) }
