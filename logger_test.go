package authboss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type (
	testLogger    struct{}
	testCtxLogger struct{}
)

func (t testLogger) Info(string)  {}
func (t testLogger) Error(string) {}

func (t testLogger) FromContext(ctx context.Context) Logger { return testCtxLogger{} }
func (t testLogger) FromRequest(r *http.Request) Logger     { return testLogger{} }

func (t testCtxLogger) Info(string)  {}
func (t testCtxLogger) Error(string) {}

func TestLogger(t *testing.T) {
	t.Parallel()

	ab := New()
	logger := testLogger{}
	ab.Config.Core.Logger = logger

	if logger != ab.Logger(nil).(testLogger) {
		t.Error("wanted our logger back")
	}

	if _, ok := ab.Logger(context.Background()).(testCtxLogger); !ok {
		t.Error("wanted ctx logger back")
	}

	if _, ok := ab.RequestLogger(httptest.NewRequest("GET", "/", nil)).(testLogger); !ok {
		t.Error("wanted normal logger back")
	}
}
