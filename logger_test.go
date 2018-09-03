package authboss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type (
	testLogger struct {
		info  string
		error string
	}
	testCtxLogger struct{}
)

func (t *testLogger) Info(s string) {
	t.info += s
}
func (t *testLogger) Error(s string) {
	t.error += s
}

func (t testLogger) FromContext(ctx context.Context) Logger { return testCtxLogger{} }
func (t testLogger) FromRequest(r *http.Request) Logger     { return &testLogger{} }

func (t testCtxLogger) Info(string)  {}
func (t testCtxLogger) Error(string) {}

func TestLogger(t *testing.T) {
	t.Parallel()

	ab := New()
	logger := &testLogger{}
	ab.Config.Core.Logger = logger

	if logger != ab.Logger(nil).Logger.(*testLogger) {
		t.Error("wanted our logger back")
	}

	if _, ok := ab.Logger(context.Background()).Logger.(testCtxLogger); !ok {
		t.Error("wanted ctx logger back")
	}

	if _, ok := ab.RequestLogger(httptest.NewRequest("GET", "/", nil)).Logger.(*testLogger); !ok {
		t.Error("wanted normal logger back")
	}
}

func TestFmtLogger(t *testing.T) {
	t.Parallel()

	logger := &testLogger{}
	fmtlog := FmtLogger{logger}

	fmtlog.Errorf("%s %s", "ok", "go")
	fmtlog.Infof("%s %s", "go", "ok")

	if logger.error != "ok go" {
		t.Error("wrong output", logger.error)
	}
	if logger.info != "go ok" {
		t.Error("wrong output", logger.info)
	}
}
