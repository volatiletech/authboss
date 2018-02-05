package defaults

import (
	"os"

	"github.com/volatiletech/authboss"
)

// SetDefaultCore creates instances of all the default pieces
//
// Assumes you have a ViewRenderer already set.
func SetDefaultCore(config *authboss.Config, useUsername bool) {
	logger := NewLogger(os.Stdout)

	config.Core.Router = NewRouter()
	config.Core.ErrorHandler = ErrorHandler{LogWriter: logger}
	config.Core.Responder = &Responder{Renderer: config.Core.ViewRenderer}
	config.Core.Redirector = &Redirector{Renderer: config.Core.ViewRenderer, FormValueName: "redir"}
	config.Core.BodyReader = NewHTTPFormReader(useUsername)
	config.Core.Mailer = NewLogMailer(os.Stdout)
	config.Core.Logger = logger
}
