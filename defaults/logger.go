package defaults

import (
	"fmt"
	"io"
	"time"
)

// Logger writes exactly once for each log line to underlying io.Writer
// that's passed in and ends each message with a newline.
// It has RFC3339 as a date format, and emits a log level.
type Logger struct {
	Writer io.Writer
}

// NewLogger creates a new logger from an io.Writer
func NewLogger(writer io.Writer) Logger {
	return Logger{Writer: writer}
}

// Info logs go here
func (l Logger) Info(s string) {
	fmt.Fprintf(l.Writer, "%s [INFO]: %s\n", time.Now().UTC().Format(time.RFC3339), s)
}

// Error logs go here
func (l Logger) Error(s string) {
	fmt.Fprintf(l.Writer, "%s [ERROR]: %s\n", time.Now().UTC().Format(time.RFC3339), s)
}
