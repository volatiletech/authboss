package authboss

import (
	"errors"
	"fmt"
	"reflect"
	"time"
	"unicode"
)

// UserNotFound should be returned from Get when the record is not found.
var UserNotFound = errors.New("User not found")

// TokenNotFound should be returned from UseToken when the record is not found.
var TokenNotFound = errors.New("Token not found")

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
	// must be a struct thot contains a field with the correct type as shown
	// by attrMeta. If the key is not found in the data store simply
	// return nil, UserNotFound.
	Get(key string, attrMeta AttributeMeta) (interface{}, error)
}

// TokenStorer must be implemented in order to satisfy the remember module's
// storage requirements.
type TokenStorer interface {
	Storer
	// AddToken saves a new token for the key.
	AddToken(key, token string) error
	// DelTokens removes all tokens for a given key.
	DelTokens(key string) error
	// UseToken finds the key-token pair, removes the entry in the store
	// and returns the key that was found. If the token could not be found
	// return "", TokenNotFound
	UseToken(givenKey, token string) (key string, err error)
}

// DataType represents the various types that clients must be able to store.
type DataType int

const (
	Integer DataType = iota
	String
	DateTime
)

var dateTimeType = reflect.TypeOf(time.Time{})

func (d DataType) String() string {
	switch d {
	case Integer:
		return "Integer"
	case String:
		return "String"
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

// Attribute is data along with type information.
type Attribute struct {
	Type  DataType
	Value interface{}
}

// Attributes is just a key-value mapping of data.
type Attributes map[string]Attribute

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
		if _, has := structType.FieldByName(k); !has {
			return fmt.Errorf("Bind: Struct was missing %s field, type: %v", k, v.Type)
		}

		field := structVal.FieldByName(k)
		if !field.CanSet() {
			return fmt.Errorf("Bind: Found field %s, but was not writeable.", k)
		}

		fieldKind := field.Kind()
		fieldType := field.Type()
		switch v.Type {
		case Integer:
			if fieldKind != reflect.Int {
				return fmt.Errorf("Bind: Field %s's type should be %s but was %s", k, reflect.Int.String(), fieldType)
			}
			field.SetInt(int64(v.Value.(int)))
		case String:
			if fieldKind != reflect.String {
				return fmt.Errorf("Bind: Field %s's type should be %s but was %s", k, reflect.String.String(), fieldType)
			}
			field.SetString(v.Value.(string))
		case DateTime:
			timeType := dateTimeType
			if fieldType != timeType {
				return fmt.Errorf("Bind: Field %s's type should be %s but was %s", k, timeType.String(), fieldType)
			}
			field.Set(reflect.ValueOf(v.Value))
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

		switch field.Kind() {
		case reflect.Struct:
			if field.Type() == dateTimeType {
				attr[name] = Attribute{
					Type:  DateTime,
					Value: field.Interface(),
				}
			}
		case reflect.Int:
			attr[name] = Attribute{
				Type:  Integer,
				Value: field.Interface(),
			}
		case reflect.String:
			attr[name] = Attribute{
				Type:  String,
				Value: field.Interface(),
			}
		}
	}

	return attr
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
