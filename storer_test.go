package authboss

import (
	"strings"
	"testing"
	"time"
)

type testStorer int

func (t testStorer) Create(key string, attr Attributes) error                    { return nil }
func (t testStorer) Put(key string, attr Attributes) error                       { return nil }
func (t testStorer) Get(key string, attrMeta AttributeMeta) (interface{}, error) { return nil, nil }

func TestAttributes_Bind(t *testing.T) {
	anInteger := 5
	aString := "string"
	aTime := time.Now()

	data := Attributes{
		"Integer": Attribute{Integer, anInteger},
		"String":  Attribute{String, aString},
		"Date":    Attribute{DateTime, aTime},
	}

	s := struct {
		Integer int
		String  string
		Date    time.Time
	}{}

	if err := data.Bind(&s); err != nil {
		t.Error("Unexpected Error:", err)
	}

	if s.Integer != anInteger {
		t.Error("Integer was not set.")
	}
	if s.String != aString {
		t.Error("String was not set.")
	}
	if s.Date != aTime {
		t.Error("Time was not set.")
	}
}

func TestAttributes_BindNoPtr(t *testing.T) {
	data := Attributes{}
	s := struct{}{}

	if err := data.Bind(s); err == nil {
		t.Error("Expected an error.")
	} else if !strings.Contains(err.Error(), "struct pointer") {
		t.Error("Expected an error about pointers got:", err)
	}
}

func TestAttributes_BindMissingField(t *testing.T) {
	data := Attributes{"Integer": Attribute{Integer, 5}}
	s := struct{}{}

	if err := data.Bind(&s); err == nil {
		t.Error("Expected an error.")
	} else if !strings.Contains(err.Error(), "missing") {
		t.Error("Expected an error about missing fields, got:", err)
	}
}

func TestAttributes_BindTypeFail(t *testing.T) {
	tests := []struct {
		Attr   Attributes
		Err    string
		ToBind interface{}
	}{
		{
			Attr: Attributes{"Integer": Attribute{Integer, 5}},
			Err:  "should be int",
			ToBind: &struct {
				Integer string
			}{},
		},
		{
			Attr: Attributes{"String": Attribute{String, ""}},
			Err:  "should be string",
			ToBind: &struct {
				String int
			}{},
		},
		{
			Attr: Attributes{"Date": Attribute{DateTime, time.Time{}}},
			Err:  "should be time.Time",
			ToBind: &struct {
				Date int
			}{},
		},
	}

	for i, test := range tests {
		if err := test.Attr.Bind(test.ToBind); err == nil {
			t.Errorf("%d> Expected an error.", i)
		} else if !strings.Contains(err.Error(), test.Err) {
			t.Errorf("%d> Expected an error about %q got: %q", i, test.Err, err)
		}
	}

}

func TestAttributes_Unbind(t *testing.T) {
	s1 := struct {
		Integer int
		String  string
		Time    time.Time

		SomethingElse1 int32
		SomethingElse2 *Config

		unexported int
	}{5, "string", time.Now(), 5, nil, 5}

	attr := Unbind(s1)
	if len(attr) != 3 {
		t.Error("Expected three fields, got:", len(attr))
	}

	if v, ok := attr["Integer"]; !ok {
		t.Error("Could not find Integer entry.")
	} else if v.Type != Integer {
		t.Error("Described type is wrong:", v.Type)
	} else if i, ok := v.Value.(int); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if s1.Integer != i {
		t.Error("Underlying value is wrong:", i)
	}

	if v, ok := attr["String"]; !ok {
		t.Error("Could not find String entry.")
	} else if v.Type != String {
		t.Error("Described type is wrong:", v.Type)
	} else if s, ok := v.Value.(string); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if s1.String != s {
		t.Error("Underlying value is wrong:", s)
	}

	if v, ok := attr["Time"]; !ok {
		t.Error("Could not find Time entry.")
	} else if v.Type != DateTime {
		t.Error("Described type is wrong:", v.Type)
	} else if i, ok := v.Value.(time.Time); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if s1.Time != i {
		t.Error("Underlying value is wrong:", i)
	}
}
