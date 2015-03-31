package authboss

import "testing"

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
