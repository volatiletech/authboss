package authboss

import (
	"context"
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
func (a *Authboss) RequestLogger(r *http.Request) Logger {
	logger := a.Config.Core.Logger
	if reqLogger, ok := logger.(RequestLogger); ok {
		return reqLogger.FromRequest(r)
	}

	return a.Logger(r.Context())
}

// Logger returns an appopriate logger for the context:
// If context is nil, then it simply returns the configured
// logger.
// If context is not nil, then it will attempt to upgrade
// the configured logger to a ContextLogger, and create
// a context-specific logger for use.
func (a *Authboss) Logger(ctx context.Context) Logger {
	logger := a.Config.Core.Logger
	if ctx == nil {
		return logger
	}

	ctxLogger, ok := logger.(ContextLogger)
	if !ok {
		return logger
	}

	return ctxLogger.FromContext(ctx)
}
