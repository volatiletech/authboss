package authboss

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
)

func TestDefaultLogger(t *testing.T) {
	t.Parallel()

	logger := NewDefaultLogger()
	if logger == nil {
		t.Error("Logger was not created.")
	}
}

func TestDefaultLoggerOutput(t *testing.T) {
	t.Parallel()

	buffer := &bytes.Buffer{}
	logger := (*DefaultLogger)(log.New(buffer, "", log.LstdFlags))
	io.WriteString(logger, "hello world")
	if s := buffer.String(); !strings.HasSuffix(s, "hello world\n") {
		t.Error("Output was wrong:", s)
	}
}
