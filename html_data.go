package authboss

import (
	"context"
	"net/http"
)

// Keys for use in HTMLData that are meaningful
const (
	// DataErr is for one off errors that don't really belong to
	// a particular field. It should be a string.
	DataErr = "error"
	// DataValidation is for validation errors, it should always
	// have been created using the Map() style functions in the
	// validation method so that html/text template users don't
	// struggle in displaying them.
	//
	// It is: map[string][]string, where the key in the map is the field
	// and the []string on the other side is the list of problems
	// with that field.
	//
	// It's also important to note that if the errors that were Map()'d
	// did not implement FieldError or for generic errors
	// the empty string ("") is used as a key in the map for those
	// errors that couldn't be fit to a specific field.
	DataValidation = "errors"
	// DataPreserve preserves fields during large form exercises
	// like user registration so we don't have to re-type safe
	// information like addresses etc.
	//
	// This data looks like map[string]string, and is simply
	// keyed by the field name, and the value is the field value.
	DataPreserve = "preserve"
	// DataModules contains a map[string]bool of which modules are loaded
	// The bool is largely extraneous and can be ignored, if the module is
	// loaded it will be present in the map, if not it will be missing.
	DataModules = "modules"
)

// HTMLData is used to render templates with.
type HTMLData map[string]interface{}

// NewHTMLData creates HTMLData from key-value pairs. The input is a key-value
// slice, where odd elements are keys, and the following even element
// is their value.
func NewHTMLData(data ...interface{}) HTMLData {
	if len(data)%2 != 0 {
		panic("it should be a key value list of arguments.")
	}

	h := make(HTMLData)

	for i := 0; i < len(data)-1; i += 2 {
		k, ok := data[i].(string)
		if !ok {
			panic("Keys must be strings.")
		}

		h[k] = data[i+1]
	}

	return h
}

// Merge adds the data from other to h. If there are conflicting keys
// they are overwritten by other's values.
func (h HTMLData) Merge(other HTMLData) HTMLData {
	for k, v := range other {
		h[k] = v
	}
	return h
}

// MergeKV adds extra key-values to the HTMLData. The input is a key-value
// slice, where odd elements are keys, and the following even element
// is their value.
func (h HTMLData) MergeKV(data ...interface{}) HTMLData {
	if len(data)%2 != 0 {
		panic("It should be a key value list of arguments.")
	}

	for i := 0; i < len(data)-1; i += 2 {
		k, ok := data[i].(string)
		if !ok {
			panic("Keys must be strings.")
		}

		h[k] = data[i+1]
	}

	return h
}

// MergeDataInRequest edits the request pointer to point to a new request with
// a modified context that contains the merged data.
func MergeDataInRequest(r **http.Request, other HTMLData) {
	ctx := (*r).Context()
	currentIntf := ctx.Value(CTXKeyData)
	if currentIntf == nil {
		*r = (*r).WithContext(context.WithValue(ctx, CTXKeyData, other))
		return
	}

	current := currentIntf.(HTMLData)
	merged := current.Merge(other)
	*r = (*r).WithContext(context.WithValue(ctx, CTXKeyData, merged))
}
