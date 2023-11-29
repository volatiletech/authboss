package authboss

import "context"

type Localizer interface {
	// Get the translation for the given text in the given context.
	// If no translation is found, an empty string should be returned.
	Localize(ctx context.Context, txt string, args ...any) string
}
