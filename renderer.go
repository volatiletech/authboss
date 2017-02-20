package authboss

import "context"

// RenderLoader is an object that understands how to load display templates.
// It's possible that Init() is a no-op if the responses are JSON or anything
// else.
type RenderLoader interface {
	Init(names string) (Renderer, error)
}

// Renderer is a type that can render a given template with some data.
type Renderer interface {
	Render(ctx context.Context, data HTMLData) ([]byte, error)
}
