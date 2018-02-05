package authboss

import "context"

// Renderer is a type that can render a given template with some data.
type Renderer interface {
	// Load the given templates, will most likely be called multiple times
	Load(names ...string) error

	// Render the given template
	Render(ctx context.Context, page string, data HTMLData) (output []byte, contentType string, err error)
}
