// Package validate supports validation of usernames, email addresses, and passwords.
package validate

import (
	"fmt"

	"gopkg.in/authboss.v0"
)

var V *Validate

func init() {
	V = &Validate{}
	authboss.RegisterModule("validate", V)
}

const (
	policyEmail    = "email"
	policyUsername = "username"
	policyPassword = "password"
)

type Validate struct {
	Email    authboss.Validator
	Username authboss.Validator
	Password authboss.Validator
}

func (v *Validate) Initialize(config *authboss.Config) error {
	policies := authboss.FilterValidators(config.Policies, policyEmail, policyUsername, policyPassword)

	if v.Email = policies[0]; v.Email.Field() != policyEmail {
		return fmt.Errorf("validate: missing policy: %s", policyEmail)
	}

	if v.Username = policies[1]; v.Username.Field() != policyUsername {
		return fmt.Errorf("validate: missing policy: %s", policyUsername)
	}

	if v.Password = policies[2]; v.Password.Field() != policyPassword {
		return fmt.Errorf("validate: missing policy: %s", policyPassword)
	}

	config.Callbacks.Before(authboss.EventRegister, v.BeforeRegister)
	config.Callbacks.Before(authboss.EventRecoverStart, v.BeforeRegister)
	config.Callbacks.Before(authboss.EventRecoverEnd, v.BeforeRegister)

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
