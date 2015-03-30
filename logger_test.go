package authboss

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
)

func TestDefaultLogger(t *testing.T) {
	logger := NewDefaultLogger()
	if logger == nil {
		t.Error("Logger was not created.")
	}
}

func TestDefaultLoggerOutput(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := (*DefaultLogger)(log.New(buffer, "", log.LstdFlags))
	io.WriteString(logger, "hello world")
	if s := buffer.String(); !strings.HasSuffix(s, "hello world\n") {
		t.Error("Output was wrong:", s)
	}
}
