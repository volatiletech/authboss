package authboss

import "fmt"

// AttributeErr represents a failure to retrieve a critical
// piece of data from the storer.
type AttributeErr struct {
	Name     string
	WantKind DataType
	GotKind  string
}

// NewAttributeErr creates a new attribute err type. Useful for when you want
// to have a type mismatch error.
func NewAttributeErr(name string, kind DataType, val interface{}) AttributeErr {
	return AttributeErr{
		Name:     name,
		WantKind: kind,
		GotKind:  fmt.Sprintf("%T", val),
	}
}

func (a AttributeErr) Error() string {
	if len(a.GotKind) == 0 {
		return fmt.Sprintf("Failed to retrieve database attribute: %s", a.Name)
	}

	return fmt.Sprintf("Failed to retrieve database attribute, type was wrong: %s (want: %v, got: %s)", a.Name, a.WantKind, a.GotKind)
}

// ClientDataErr represents a failure to retrieve a critical
// piece of client information such as a cookie or session value.
type ClientDataErr struct {
	Name string
}

func (c ClientDataErr) Error() string {
	return fmt.Sprintf("Failed to retrieve client attribute: %s", c.Name)
}

// ErrAndRedirect represents a general error whose response should
// be to redirect.
type ErrAndRedirect struct {
	Err          error
	Location     string
	FlashSuccess string
	FlashError   string
}

func (e ErrAndRedirect) Error() string {
	return fmt.Sprintf("Error: %v, Redirecting to: %s", e.Err, e.Location)
}

// RenderErr represents an error that occured during rendering
// of a template.
type RenderErr struct {
	TemplateName string
	Data         interface{}
	Err          error
}

func (r RenderErr) Error() string {
	return fmt.Sprintf("Error rendering template %q: %v, data: %#v", r.TemplateName, r.Err, r.Data)
}
