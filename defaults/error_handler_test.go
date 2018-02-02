package defaults

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkg/errors"
)

func TestErrorHandler(t *testing.T) {
	t.Parallel()

	b := &bytes.Buffer{}

	eh := ErrorHandler{LogWriter: b}

	handler := eh.Wrap(func(w http.ResponseWriter, r *http.Request) error {
		return errors.New("error occurred")
	})
	// Assert that it's the right type
	var _ http.Handler = handler

	handler.ServeHTTP(nil, httptest.NewRequest("GET", "/target", nil))

	if !strings.Contains(b.String(), "error at /target: error occurred") {
		t.Error("output was wrong:", b.String())
	}
}
