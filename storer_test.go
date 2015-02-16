package authboss

import (
	"strings"
	"testing"
	"time"
)

func TestAttributes_Names(t *testing.T) {
	t.Parallel()

	attr := Attributes{
		"integer":   5,
		"string":    "string",
		"bool":      true,
		"date_time": time.Now(),
	}
	names := attr.Names()

	found := map[string]bool{"integer": false, "string": false, "bool": false, "date_time": false}
	for _, n := range names {
		found[n] = true
	}

	for k, v := range found {
		if !v {
			t.Error("Could not find:", k)
		}
	}
}

func TestAttributeMeta_Names(t *testing.T) {
	t.Parallel()

	meta := AttributeMeta{
		"integer":   Integer,
		"string":    String,
		"bool":      Bool,
		"date_time": DateTime,
	}
	names := meta.Names()

	found := map[string]bool{"integer": false, "string": false, "bool": false, "date_time": false}
	for _, n := range names {
		found[n] = true
	}

	for k, v := range found {
		if !v {
			t.Error("Could not find:", k)
		}
	}
}

func TestDataType_String(t *testing.T) {
	t.Parallel()

	if Integer.String() != "Integer" {
		t.Error("Expected Integer:", Integer)
	}
	if String.String() != "String" {
		t.Error("Expected String:", String)
	}
	if Bool.String() != "Bool" {
		t.Error("Expected Bool:", String)
	}
	if DateTime.String() != "DateTime" {
		t.Error("Expected DateTime:", DateTime)
	}
}

func TestAttributes_Bind(t *testing.T) {
	t.Parallel()

	anInteger := 5
	aString := "string"
	aBool := true
	aTime := time.Now()

	data := Attributes{
		"integer":   anInteger,
		"string":    aString,
		"bool":      aBool,
		"date_time": aTime,
	}

	s := struct {
		Integer  int
		String   string
		Bool     bool
		DateTime time.Time
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
	if s.Bool != aBool {
		t.Error("Bool was not set.")
	}
	if s.DateTime != aTime {
		t.Error("DateTime was not set.")
	}
}

func TestAttributes_BindNoPtr(t *testing.T) {
	t.Parallel()

	data := Attributes{}
	s := struct{}{}

	if err := data.Bind(s); err == nil {
		t.Error("Expected an error.")
	} else if !strings.Contains(err.Error(), "struct pointer") {
		t.Error("Expected an error about pointers got:", err)
	}
}

func TestAttributes_BindMissingField(t *testing.T) {
	t.Parallel()

	data := Attributes{"Integer": 5}
	s := struct{}{}

	if err := data.Bind(&s); err == nil {
		t.Error("Expected an error.")
	} else if !strings.Contains(err.Error(), "missing") {
		t.Error("Expected an error about missing fields, got:", err)
	}
}

func TestAttributes_BindTypeFail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Attr   Attributes
		Err    string
		ToBind interface{}
	}{
		{
			Attr: Attributes{"integer": 5},
			Err:  "should be int",
			ToBind: &struct {
				Integer string
			}{},
		},
		{
			Attr: Attributes{"string": ""},
			Err:  "should be string",
			ToBind: &struct {
				String int
			}{},
		},
		{
			Attr: Attributes{"bool": true},
			Err:  "should be bool",
			ToBind: &struct {
				Bool string
			}{},
		},
		{
			Attr: Attributes{"date": time.Time{}},
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
	t.Parallel()

	s1 := struct {
		Integer int
		String  string
		Bool    bool
		Time    time.Time

		SomethingElse1 int32
		SomethingElse2 *Config

		unexported int
	}{5, "string", true, time.Now(), 5, nil, 5}

	attr := Unbind(&s1)
	if len(attr) != 4 {
		t.Error("Expected three fields, got:", len(attr))
	}

	if v, ok := attr["integer"]; !ok {
		t.Error("Could not find Integer entry.")
	} else if val, ok := v.(int); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if s1.Integer != val {
		t.Error("Underlying value is wrong:", val)
	}

	if v, ok := attr["string"]; !ok {
		t.Error("Could not find String entry.")
	} else if val, ok := v.(string); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if s1.String != val {
		t.Error("Underlying value is wrong:", val)
	}

	if v, ok := attr["bool"]; !ok {
		t.Error("Could not find String entry.")
	} else if val, ok := v.(bool); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if s1.Bool != val {
		t.Error("Underlying value is wrong:", val)
	}

	if v, ok := attr["time"]; !ok {
		t.Error("Could not find Time entry.")
	} else if val, ok := v.(time.Time); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if s1.Time != val {
		t.Error("Underlying value is wrong:", val)
	}
}

func TestCasingStyleConversions(t *testing.T) {
	t.Parallel()

	camel := "SomethingInCamel"

	got := camelToUnder(camel)
	if got != "something_in_camel" {
		t.Error(got)
	}

	got = underToCamel(got)
	if got != camel {
		t.Error(got)
	}
}
