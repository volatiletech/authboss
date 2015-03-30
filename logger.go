package authboss

import (
	"log"
	"os"
)

// DefaultLogger is a basic logger.
type DefaultLogger log.Logger

// NewDefaultLogger creates a logger to stdout.
func NewDefaultLogger() *DefaultLogger {
	return ((*DefaultLogger)(log.New(os.Stdout, "", log.LstdFlags)))
}

// Write writes to the internal logger.
func (d *DefaultLogger) Write(b []byte) (int, error) {
	((*log.Logger)(d)).Printf("%s", b)
	return len(b), nil
}
