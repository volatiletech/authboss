// Package validate supports validation of usernames, email addresses, and passwords.
package validate

import "gopkg.in/authboss.v0"

var V *Validate

func init() {
	V = &Validate{}
	authboss.RegisterModule("validate", V)
}

type Validate struct {
	Username authboss.Validator
	Password authboss.Validator
	Email    authboss.Validator
}

func (v *Validate) Initialize(config *authboss.Config) error {
	v.Email = config.ValidateEmail
	v.Username = config.ValidateUsername
	v.Password = config.ValidatePassword

	config.Callbacks.Before(authboss.EventRegister, v.BeforeRegister)

	return nil
}

func (v *Validate) Routes() authboss.RouteTable      { return nil }
func (v *Validate) Storage() authboss.StorageOptions { return nil }

func (v *Validate) BeforeRegister(ctx *authboss.Context) error {
	errList := make(authboss.ErrorList, 0)

	if v.Email != nil {
		email, ok := ctx.FirstPostFormValue("email")
		if ok {
			errs := v.Email.Errors(email)
			errList = append(errList, errs...)
		}
	}

	if v.Username != nil {
		username, ok := ctx.FirstPostFormValue("username")
		if ok {
			errs := v.Username.Errors(username)
			errList = append(errList, errs...)
		}
	}

	if v.Password != nil {
		password, ok := ctx.FirstPostFormValue("password")
		if ok {
			errs := v.Password.Errors(password)
			errList = append(errList, errs...)
		}
	}

	return errList
}
