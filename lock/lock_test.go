package lock

import "testing"

func TestStorage(t *testing.T) {
	storage := L.Storage()
	if _, ok := storage[UserAttemptNumber]; !ok {
		t.Error("Expected attempt number storage option.")
	}
	if _, ok := storage[UserAttemptTime]; !ok {
		t.Error("Expected attempt number time option.")
	}
}
