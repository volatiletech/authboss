package authboss

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"time"
	"unicode"
)

// Data store constants for attribute names.
const (
	StoreEmail    = "email"
	StoreUsername = "username"
	StorePassword = "password"
)

// Data store constants for OAuth2 attribute names.
const (
	StoreOAuth2UID      = "oauth2_uid"
	StoreOAuth2Provider = "oauth2_provider"
	StoreOAuth2Token    = "oauth2_token"
	StoreOAuth2Refresh  = "oauth2_refresh"
	StoreOAuth2Expiry   = "oauth2_expiry"
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
	// Put is for storing the attributes passed in using the key. This is an
	// update only method and should not store if it does not find the key.
	Put(key string, attr Attributes) error
	// Get is for retrieving attributes for a given key. The return value
	// must be a struct that contains all fields with the correct types as shown
	// by attrMeta. If the key is not found in the data store simply
	// return nil, ErrUserNotFound.
	Get(key string) (interface{}, error)
}

// OAuth2Storer is a replacement (or addition) to the Storer interface.
// It allows users to be stored and fetched via a uid/provider combination.
type OAuth2Storer interface {
	// PutOAuth creates or updates an existing record (unlike Storer.Put)
	// because in the OAuth flow there is no separate create/update.
	PutOAuth(uid, provider string, attr Attributes) error
	GetOAuth(uid, provider string) (interface{}, error)
}

// DataType represents the various types that clients must be able to store.
type DataType int

// DataType constants
const (
	Integer DataType = iota
	String
	Bool
	DateTime
)

var (
	dateTimeType = reflect.TypeOf(time.Time{})
)

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
	for n := range a {
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
	for n := range a {
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

// Int64 returns a single value as a int64
func (a Attributes) Int64(key string) (int64, bool) {
	inter, ok := a[key]
	if !ok {
		return 0, false
	}
	val, ok := inter.(int64)
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

// StringErr returns a single value as a string
func (a Attributes) StringErr(key string) (val string, err error) {
	inter, ok := a[key]
	if !ok {
		return "", AttributeErr{Name: key}
	}
	val, ok = inter.(string)
	if !ok {
		return val, NewAttributeErr(key, String, inter)
	}
	return val, nil
}

// Int64Err returns a single value as a int
func (a Attributes) Int64Err(key string) (val int64, err error) {
	inter, ok := a[key]
	if !ok {
		return val, AttributeErr{Name: key}
	}
	val, ok = inter.(int64)
	if !ok {
		return val, NewAttributeErr(key, Integer, inter)
	}
	return val, nil
}

// BoolErr returns a single value as a bool.
func (a Attributes) BoolErr(key string) (val bool, err error) {
	inter, ok := a[key]
	if !ok {
		return val, AttributeErr{Name: key}
	}
	val, ok = inter.(bool)
	if !ok {
		return val, NewAttributeErr(key, Integer, inter)
	}
	return val, nil
}

// DateTimeErr returns a single value as a time.Time
func (a Attributes) DateTimeErr(key string) (val time.Time, err error) {
	inter, ok := a[key]
	if !ok {
		return val, AttributeErr{Name: key}
	}
	val, ok = inter.(time.Time)
	if !ok {
		return val, NewAttributeErr(key, DateTime, inter)
	}
	return val, nil
}

// Bind the data in the attributes to the given struct. This means the
// struct creator must have read the documentation and decided what fields
// will be needed ahead of time. Ignore missing ignores attributes for
// which a struct attribute equivalent can not be found.
func (a Attributes) Bind(strct interface{}, ignoreMissing bool) error {
	structType := reflect.TypeOf(strct)
	if structType.Kind() != reflect.Ptr {
		return errors.New("Bind: Must pass in a struct pointer.")
	}

	structVal := reflect.ValueOf(strct).Elem()
	structType = structVal.Type()
	for k, v := range a {

		k = underToCamel(k)

		if _, has := structType.FieldByName(k); !has && ignoreMissing {
			continue
		} else if !has {
			return fmt.Errorf("Bind: Struct was missing %s field, type: %v", k, reflect.TypeOf(v).String())
		}

		field := structVal.FieldByName(k)
		if !field.CanSet() {
			return fmt.Errorf("Bind: Found field %s, but was not writeable", k)
		}

		fieldKind := field.Kind()
		fieldType := field.Type()
		fieldPtr := field.Addr()

		if _, ok := fieldPtr.Interface().(sql.Scanner); ok {
			method := fieldPtr.MethodByName("Scan")
			if !method.IsValid() {
				return errors.New("Bind: Was a scanner without a Scan method")
			}

			rvals := method.Call([]reflect.Value{reflect.ValueOf(v)})
			if err, ok := rvals[0].Interface().(error); ok && err != nil {
				return err
			}

			continue
		}

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

		fieldPtr := field.Addr()
		if _, ok := fieldPtr.Interface().(driver.Valuer); ok {
			method := fieldPtr.MethodByName("Value")
			if !method.IsValid() {
				panic("Unbind: Was a valuer without a Value method")
			}

			rvals := method.Call([]reflect.Value{})
			if err, ok := rvals[1].Interface().(error); ok && err != nil {
				panic(fmt.Errorf("Unbind: Failed to get value out of Valuer: %s, %v", name, err))
			}
			attr[name] = rvals[0].Interface()

			continue
		}

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
