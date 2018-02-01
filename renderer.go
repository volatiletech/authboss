package authboss

import "context"

// Renderer is a type that can render a given template with some data.
type Renderer interface {
	// Load the given templates, will most likely be called multiple times
	Load(name ...string) error

	// Render the given template
	Render(ctx context.Context, name string, data HTMLData) (output []byte, contentType string, err error)
}
