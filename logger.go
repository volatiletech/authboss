package authboss

import (
	"context"
	"fmt"
	"net/http"
)

// Logger is the basic logging structure that's required
type Logger interface {
	Info(string)
	Error(string)
}

// ContextLogger creates a logger from a request context
type ContextLogger interface {
	FromContext(context.Context) Logger
}

// RequestLogger creates a logger from a request
type RequestLogger interface {
	FromRequest(*http.Request) Logger
}

// RequestLogger returns a request logger if possible, if not
// it calls Logger which tries to do a ContextLogger, and if
// that fails it will finally get a normal logger.
func (a *Authboss) RequestLogger(r *http.Request) FmtLogger {
	logger := a.Config.Core.Logger
	if reqLogger, ok := logger.(RequestLogger); ok {
		return FmtLogger{reqLogger.FromRequest(r)}
	}

	return FmtLogger{a.Logger(r.Context())}
}

// Logger returns an appopriate logger for the context:
// If context is nil, then it simply returns the configured
// logger.
// If context is not nil, then it will attempt to upgrade
// the configured logger to a ContextLogger, and create
// a context-specific logger for use.
func (a *Authboss) Logger(ctx context.Context) FmtLogger {
	logger := a.Config.Core.Logger
	if ctx == nil {
		return FmtLogger{logger}
	}

	ctxLogger, ok := logger.(ContextLogger)
	if !ok {
		return FmtLogger{logger}
	}

	return FmtLogger{ctxLogger.FromContext(ctx)}
}

// FmtLogger adds convenience functions on top of the logging
// methods for formatting.
type FmtLogger struct {
	Logger
}

// Errorf prints to Error() with fmt.Printf semantics
func (f FmtLogger) Errorf(format string, values ...interface{}) {
	f.Logger.Error(fmt.Sprintf(format, values...))
}

// Infof prints to Info() with fmt.Printf semantics
func (f FmtLogger) Infof(format string, values ...interface{}) {
	f.Logger.Info(fmt.Sprintf(format, values...))
}
