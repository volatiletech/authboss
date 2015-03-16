package authboss

import (
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

type NullTime struct {
	Time  time.Time
	Valid bool
}

func (nt *NullTime) Scan(value interface{}) error {
	nt.Time, nt.Valid = value.(time.Time)
	return nil
}

func (nt NullTime) Value() (driver.Value, error) {
	if !nt.Valid {
		return nil, nil
	}
	return nt.Time, nil
}

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

func TestAttributeMeta_Helpers(t *testing.T) {
	now := time.Now()
	attr := Attributes{
		"integer":   int64(5),
		"string":    "a",
		"bool":      true,
		"date_time": now,
	}

	if str, ok := attr.String("string"); !ok || str != "a" {
		t.Error(str, ok)
	}
	if str, err := attr.StringErr("string"); err != nil || str != "a" {
		t.Error(str, err)
	}
	if str, ok := attr.String("notstring"); ok {
		t.Error(str, ok)
	}
	if str, err := attr.StringErr("notstring"); err == nil {
		t.Error(str, err)
	}

	if integer, ok := attr.Int64("integer"); !ok || integer != 5 {
		t.Error(integer, ok)
	}
	if integer, err := attr.Int64Err("integer"); err != nil || integer != 5 {
		t.Error(integer, err)
	}
	if integer, ok := attr.Int64("notinteger"); ok {
		t.Error(integer, ok)
	}
	if integer, err := attr.Int64Err("notinteger"); err == nil {
		t.Error(integer, err)
	}

	if boolean, ok := attr.Bool("bool"); !ok || !boolean {
		t.Error(boolean, ok)
	}
	if boolean, err := attr.BoolErr("bool"); err != nil || !boolean {
		t.Error(boolean, err)
	}
	if boolean, ok := attr.Bool("notbool"); ok {
		t.Error(boolean, ok)
	}
	if boolean, err := attr.BoolErr("notbool"); err == nil {
		t.Error(boolean, err)
	}

	if date, ok := attr.DateTime("date_time"); !ok || date != now {
		t.Error(date, ok)
	}
	if date, err := attr.DateTimeErr("date_time"); err != nil || date != now {
		t.Error(date, err)
	}
	if date, ok := attr.DateTime("notdate_time"); ok {
		t.Error(date, ok)
	}
	if date, err := attr.DateTimeErr("notdate_time"); err == nil {
		t.Error(date, err)
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

	if err := data.Bind(&s, false); err != nil {
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

func TestAttributes_BindIgnoreMissing(t *testing.T) {
	t.Parallel()

	anInteger := 5
	aString := "string"

	data := Attributes{
		"integer": anInteger,
		"string":  aString,
	}

	s := struct {
		Integer int
	}{}

	if err := data.Bind(&s, false); err == nil {
		t.Error("Expected error about missing attributes:", err)
	}

	if err := data.Bind(&s, true); err != nil {
		t.Error(err)
	}

	if s.Integer != anInteger {
		t.Error("Integer was not set.")
	}
}

func TestAttributes_BindNoPtr(t *testing.T) {
	t.Parallel()

	data := Attributes{}
	s := struct{}{}

	if err := data.Bind(s, false); err == nil {
		t.Error("Expected an error.")
	} else if !strings.Contains(err.Error(), "struct pointer") {
		t.Error("Expected an error about pointers got:", err)
	}
}

func TestAttributes_BindMissingField(t *testing.T) {
	t.Parallel()

	data := Attributes{"Integer": 5}
	s := struct{}{}

	if err := data.Bind(&s, false); err == nil {
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
		if err := test.Attr.Bind(test.ToBind, false); err == nil {
			t.Errorf("%d> Expected an error.", i)
		} else if !strings.Contains(err.Error(), test.Err) {
			t.Errorf("%d> Expected an error about %q got: %q", i, test.Err, err)
		}
	}

}

func TestAttributes_BindScannerValues(t *testing.T) {
	t.Parallel()

	s1 := struct {
		Count sql.NullInt64
		Time  NullTime
	}{
		sql.NullInt64{},
		NullTime{},
	}

	nowTime := time.Now()

	attrs := Attributes{"count": 12, "time": nowTime}
	if err := attrs.Bind(&s1, false); err != nil {
		t.Error("Unexpected error:", err)
	}

	if !s1.Count.Valid {
		t.Error("Expected valid NullInt64")
	}
	if s1.Count.Int64 != 12 {
		t.Error("Unexpected value:", s1.Count.Int64)
	}

	if !s1.Time.Valid {
		t.Error("Expected valid time.Time")
	}
	if !s1.Time.Time.Equal(nowTime) {
		t.Error("Unexpected value:", s1.Time.Time)
	}
}

func TestUnbind(t *testing.T) {
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
		t.Error("Expected 4 fields, got:", len(attr))
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

func TestUnbind_Valuer(t *testing.T) {
	t.Parallel()

	nowTime := time.Now()

	s1 := struct {
		Count sql.NullInt64
		Time  NullTime
	}{
		sql.NullInt64{Int64: 12, Valid: true},
		NullTime{nowTime, true},
	}

	attr := Unbind(&s1)

	if v, ok := attr["count"]; !ok {
		t.Error("Could not find NullInt64 entry.")
	} else if val, ok := v.(int64); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if 12 != val {
		t.Error("Underlying value is wrong:", val)
	}

	if v, ok := attr["time"]; !ok {
		t.Error("Could not find NulLTime entry.")
	} else if val, ok := v.(time.Time); !ok {
		t.Errorf("Underlying type is wrong: %T", v)
	} else if !nowTime.Equal(val) {
		t.Error("Underlying value is wrong:", val)
	}
}

func TestCasingStyleConversions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In  string
		Out string
	}{
		{"SomethingInCamel", "something_in_camel"},
		{"Oauth2Anything", "oauth2_anything"},
	}

	for i, test := range tests {
		out := camelToUnder(test.In)
		if out != test.Out {
			t.Errorf("%d) Expected %q got %q", i, test.Out, out)
		}
		out = underToCamel(out)
		if out != test.In {
			t.Errorf("%d), Expected %q got %q", i, test.In, out)
		}
	}
}
