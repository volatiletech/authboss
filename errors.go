package authboss

import "fmt"

// ClientDataErr represents a failure to retrieve a critical
// piece of client information such as a cookie or session value.
type ClientDataErr struct {
	Name string
}

func (c ClientDataErr) Error() string {
	return fmt.Sprintf("Failed to retrieve client attribute: %s", c.Name)
}

// RenderErr represents an error that occured during rendering
// of a template.
type RenderErr struct {
	TemplateName string
	Data         interface{}
	Err          error
}

func (r RenderErr) Error() string {
	return fmt.Sprintf("error rendering response %q: %v, data: %#v", r.TemplateName, r.Err, r.Data)
}
