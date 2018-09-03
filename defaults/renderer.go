package defaults

import (
	"context"
	"encoding/json"

	"github.com/volatiletech/authboss"
)

// There is a separate package that does HTML Rendering authboss-renderer

// JSONRenderer simply renders the data provided in JSON
type JSONRenderer struct {
}

// Load is a no-op since json doesn't require any templates
func (JSONRenderer) Load(names ...string) error {
	return nil
}

// Render the data
func (JSONRenderer) Render(ctx context.Context, page string, data authboss.HTMLData) (output []byte, contentType string, err error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, "", err
	}

	return b, "application/json", nil
}
