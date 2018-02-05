package defaults

import (
	"net/http"
	"net/url"
	"regexp"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
)

// FormValue types
const (
	FormValueEmail    = "email"
	FormValuePassword = "password"
	FormValueUsername = "username"
)

// UserValues from the login form
type UserValues struct {
	HTTPFormValidator

	PID      string
	Password string
}

// GetPID from the values
func (u UserValues) GetPID() string {
	return u.PID
}

// GetPassword from the values
func (u UserValues) GetPassword() string {
	return u.Password
}

// HTTPFormReader reads forms from various pages and decodes
// them.
type HTTPFormReader struct {
	UseUsername bool
	Rulesets    map[string][]Rules
}

// NewHTTPFormReader creates a form reader with default validation rules
// for each page.
func NewHTTPFormReader(useUsernameNotEmail bool) *HTTPFormReader {
	var pid string
	var pidRules Rules

	if useUsernameNotEmail {
		pid = "username"
		pidRules = Rules{
			FieldName: pid, Required: true,
			MatchError: "Usernames must only start with letters, and contain letters and numbers",
			MustMatch:  regexp.MustCompile(`(?i)[a-z][a-z0-9]?`),
		}
	} else {
		pid = "email"
		pidRules = Rules{
			FieldName: pid, Required: true,
			MatchError: "Must be a valid e-mail address",
			MustMatch:  regexp.MustCompile(`.*@.*\.[a-z]{1,}`),
		}
	}

	passwordRule := Rules{
		FieldName:  "password",
		MinLength:  8,
		MinNumeric: 1,
		MinSymbols: 1,
		MinUpper:   1,
		MinLower:   1,
	}

	return &HTTPFormReader{
		UseUsername: useUsernameNotEmail,
		Rulesets: map[string][]Rules{
			"login": []Rules{pidRules, passwordRule},
		},
	}
}

// Read the form pages
func (h HTTPFormReader) Read(page string, r *http.Request) (authboss.Validator, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.Wrapf(err, "failed to parse form on page: %s", page)
	}

	rules := h.Rulesets[page]
	values := URLValuesToMap(r.Form)

	switch page {
	case "login":
		var pid string
		if h.UseUsername {
			pid = values[FormValueUsername]
		} else {
			pid = values[FormValueEmail]
		}

		validator := HTTPFormValidator{
			Values:        values,
			Ruleset:       rules,
			ConfirmFields: []string{FormValuePassword, authboss.ConfirmPrefix + FormValuePassword},
		}
		password := values[FormValuePassword]

		return UserValues{
			HTTPFormValidator: validator,
			PID:               pid,
			Password:          password,
		}, nil
	default:
		return nil, errors.Errorf("failed to parse unknown page's form: %s", page)
	}
}

// URLValuesToMap helps create a map from url.Values
func URLValuesToMap(form url.Values) map[string]string {
	values := make(map[string]string)

	for k, v := range form {
		if len(v) != 0 {
			values[k] = v[0]
		}
	}

	return values
}
