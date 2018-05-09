package authboss

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestHTMLData(t *testing.T) {
	t.Parallel()

	data := NewHTMLData("a", "b").MergeKV("c", "d").Merge(NewHTMLData("e", "f"))
	if data["a"].(string) != "b" {
		t.Error("A was wrong:", data["a"])
	}
	if data["c"].(string) != "d" {
		t.Error("C was wrong:", data["c"])
	}
	if data["e"].(string) != "f" {
		t.Error("E was wrong:", data["e"])
	}
}

func TestHTMLData_Panics(t *testing.T) {
	t.Parallel()

	nPanics := 0
	panicCount := func() {
		if r := recover(); r != nil {
			nPanics++
		}
	}

	func() {
		defer panicCount()
		NewHTMLData("hello")
	}()

	func() {
		defer panicCount()
		NewHTMLData().MergeKV("hello")
	}()

	func() {
		defer panicCount()
		NewHTMLData(5, 6)
	}()

	func() {
		defer panicCount()
		NewHTMLData().MergeKV(7, 8)
	}()

	if nPanics != 4 {
		t.Error("They all should have paniced.")
	}
}

func TestHTMLDataMergeDataInRequest(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "/", nil)
	MergeDataInRequest(&r, HTMLData{"hello": "world"})

	val := r.Context().Value(CTXKeyData).(HTMLData)["hello"].(string)
	if val != "world" {
		t.Error("expected world, got:", val)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(context.Background(), CTXKeyData, HTMLData{"first": "here"}))
	MergeDataInRequest(&r, HTMLData{"hello": "world"})

	val = r.Context().Value(CTXKeyData).(HTMLData)["hello"].(string)
	if val != "world" {
		t.Error("expected world, got:", val)
	}

	val = r.Context().Value(CTXKeyData).(HTMLData)["first"].(string)
	if val != "here" {
		t.Error("expected world, got:", val)
	}
}
