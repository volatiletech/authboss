package authboss

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"time"
	"unicode"
)

// Data store constants for attribute names.
const (
	UserEmail    = "email"
	UserName     = "username"
	UserPassword = "password"
	// UserKey is used to uniquely identify the user.
	UserKey = UserEmail
)

var (
	// ErrUserNotFound should be returned from Get when the record is not found.
	ErrUserNotFound = errors.New("User not found")
	// ErrTokenNotFound should be returned from UseToken when the record is not found.
	ErrTokenNotFound = errors.New("Token not found")
)

// StorageOptions is a map depicting the things a module must be able to store.
type StorageOptions map[string]DataType

// Storer must be implemented in order to store the user's attributes somewhere.
// The type of store is up to the developer implementing it, and all it has to
// do is be able to store several simple types.
type Storer interface {
	// Create is the same as put, except it refers to a non-existent key.
	Create(key string, attr Attributes) error
	// Put is for storing the attributes passed in. The type information can
	// help serialization without using type assertions.
	Put(key string, attr Attributes) error
	// Get is for retrieving attributes for a given key. The return value
	// must be a struct that contains a field with the correct type as shown
	// by attrMeta. If the key is not found in the data store simply
	// return nil, ErrUserNotFound.
	Get(key string, attrMeta AttributeMeta) (interface{}, error)
}

// TokenStorer must be implemented in order to satisfy the remember module's
// storage requirements. If the implementer is a typical database then
// the tokens should be stored in a separate table since they require a 1-n
// with the user for each device the user wishes to remain logged in on.
type TokenStorer interface {
	Storer
	// AddToken saves a new token for the key.
	AddToken(key, token string) error
	// DelTokens removes all tokens for a given key.
	DelTokens(key string) error
	// UseToken finds the key-token pair, removes the entry in the store
	// and returns the key that was found. If the token could not be found
	// return "", ErrTokenNotFound
	UseToken(givenKey, token string) (key string, err error)
}

// RecoverStorer must be implemented in order to satisfy the recover module's
// storage requirements.
type RecoverStorer interface {
	Storer
	// RecoverUser looks a user up by a recover token. See recover module for
	// attribute names. If the key is not found in the data store,
	// simply return nil, ErrUserNotFound.
	RecoverUser(recoverToken string) (interface{}, error)
}

// ConfirmStorer must be implemented in order to satisfy the confirm module's
// storage requirements.
type ConfirmStorer interface {
	Storer
	// ConfirmUser looks up a user by a confirm token. See confirm module for
	// attribute names. If the token is not found in the data store,
	// simply return nil, ErrUserNotFound.
	ConfirmUser(confirmToken string) (interface{}, error)
}

// DataType represents the various types that clients must be able to store.
type DataType int

const (
	Integer DataType = iota
	String
	Bool
	DateTime
)

var dateTimeType = reflect.TypeOf(time.Time{})

func (d DataType) String() string {
	switch d {
	case Integer:
		return "Integer"
	case String:
		return "String"
	case Bool:
		return "Bool"
	case DateTime:
		return "DateTime"
	}
	return ""
}

// AttributeMeta stores type information for attributes.
type AttributeMeta map[string]DataType

// Names returns the names of all the attributes.
func (a AttributeMeta) Names() []string {
	names := make([]string, len(a))
	i := 0
	for n, _ := range a {
		names[i] = n
		i++
	}
	return names
}

// Attributes is just a key-value mapping of data.
type Attributes map[string]interface{}

// Names returns the names of all the attributes.
func (a Attributes) Names() []string {
	names := make([]string, len(a))
	i := 0
	for n, _ := range a {
		names[i] = n
		i++
	}
	return names
}

// String returns a single value as a string
func (a Attributes) String(key string) (string, bool) {
	inter, ok := a[key]
	if !ok {
		return "", false
	}
	val, ok := inter.(string)
	return val, ok
}

// Int returns a single value as a int
func (a Attributes) Int(key string) (int, bool) {
	inter, ok := a[key]
	if !ok {
		return 0, false
	}
	val, ok := inter.(int)
	return val, ok
}

// Bool returns a single value as a bool.
func (a Attributes) Bool(key string) (val bool, ok bool) {
	var inter interface{}
	inter, ok = a[key]
	if !ok {
		return val, ok
	}

	val, ok = inter.(bool)
	return val, ok
}

// DateTime returns a single value as a time.Time
func (a Attributes) DateTime(key string) (time.Time, bool) {
	inter, ok := a[key]
	if !ok {
		var time time.Time
		return time, false
	}
	val, ok := inter.(time.Time)
	return val, ok
}

// Bind the data in the attributes to the given struct. This means the
// struct creator must have read the documentation and decided what fields
// will be needed ahead of time.
func (a Attributes) Bind(strct interface{}) error {
	structType := reflect.TypeOf(strct)
	if structType.Kind() != reflect.Ptr {
		return errors.New("Bind: Must pass in a struct pointer.")
	}

	structVal := reflect.ValueOf(strct).Elem()
	structType = structVal.Type()
	for k, v := range a {

		k = underToCamel(k)

		if _, has := structType.FieldByName(k); !has {
			return fmt.Errorf("Bind: Struct was missing %s field, type: %v", k, reflect.TypeOf(v).String())
		}

		field := structVal.FieldByName(k)
		if !field.CanSet() {
			return fmt.Errorf("Bind: Found field %s, but was not writeable.", k)
		}

		fieldKind := field.Kind()
		fieldType := field.Type()
		switch val := v.(type) {
		case int:
			if fieldKind != reflect.Int {
				return fmt.Errorf("Bind: Field %s's type should be %s but was %s", k, reflect.Int.String(), fieldType)
			}
			field.SetInt(int64(val))
		case string:
			if fieldKind != reflect.String {
				return fmt.Errorf("Bind: Field %s's type should be %s but was %s", k, reflect.String.String(), fieldType)
			}
			field.SetString(val)
		case bool:
			if fieldKind != reflect.Bool {
				return fmt.Errorf("Bind: Field %s's type should be %s but was %s", k, reflect.Bool.String(), fieldType)
			}
			field.SetBool(val)
		case time.Time:
			timeType := dateTimeType
			if fieldType != timeType {
				return fmt.Errorf("Bind: Field %s's type should be %s but was %s", k, timeType.String(), fieldType)
			}
			field.Set(reflect.ValueOf(val))
		}
	}

	return nil
}

// Unbind is the opposite of Bind, taking a struct in and producing a list of attributes.
func Unbind(intf interface{}) Attributes {
	structValue := reflect.ValueOf(intf)
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}

	structType := structValue.Type()
	attr := make(Attributes)
	for i := 0; i < structValue.NumField(); i++ {
		field := structValue.Field(i)

		name := structType.Field(i).Name
		if unicode.IsLower(rune(name[0])) {
			continue // Unexported
		}

		name = camelToUnder(name)

		switch field.Kind() {
		case reflect.Struct:
			if field.Type() == dateTimeType {
				attr[name] = field.Interface()
			}
		case reflect.Bool, reflect.String, reflect.Int:
			attr[name] = field.Interface()
		}
	}

	return attr
}

func camelToUnder(in string) string {
	out := bytes.Buffer{}
	for i := 0; i < len(in); i++ {
		chr := in[i]
		if chr >= 'A' && chr <= 'Z' {
			if i > 0 {
				out.WriteByte('_')
			}
			out.WriteByte(chr + 'a' - 'A')
		} else {
			out.WriteByte(chr)
		}
	}
	return out.String()
}

func underToCamel(in string) string {
	out := bytes.Buffer{}
	for i := 0; i < len(in); i++ {
		chr := in[i]

		if first := i == 0; first || chr == '_' {
			if !first {
				i++
			}
			out.WriteByte(in[i] - 'a' + 'A')
		} else {
			out.WriteByte(chr)
		}
	}
	return out.String()
}

/*type postgresStorer struct {
	*sql.DB
}

type postgresUser struct {
	// Anything Else
	CustomAttribute string

	// AuthBoss attributes.
	Email string
}

func (p *postgresStorer) Put(key string, attr Attributes) error {
	u := postgresUser{}
	if err := attr.Bind(&u); err != nil {
		panic("I should have written my user struct better!")
	}

	_, err := p.Exec("update users set email = $1 where id = $2", u.Email, key)
	if err != nil {
		return err
	}

	return nil
}

func (p *postgresStorer) Create(key string, attr Attributes) error {
	u := postgresUser{
		CustomAttribute: "DefaultValue",
	}

	if err := attr.Bind(&u); err != nil {
		panic("I should have written my user struct better!")
	}

	_, err := p.Exec("insert into users (custom_attribute, email) values ($1)", u.CustomAttribute, u.Email)
	if err != nil {
		return err
	}

	return nil
}

func (p *postgresStorer) Get(key string, attrMeta AttributeMeta) (interface{}, error) {
	row := p.QueryRow(`select * from users where key = $1`, key)
	u := postgresUser{}
	if err := row.Scan(&u.CustomAttribute, &u.Email); err != nil {
		return nil, err
	}

	return u, nil
}*/
