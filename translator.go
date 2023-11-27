package authboss

import "context"

type Translator interface {
	// Get the translation for the given text in the given context.
	// If no translation is found, an empty string should be returned.
	Translate(ctx context.Context, txt string) string
}
