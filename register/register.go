// Package register allows for user registration.
package register

import (
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/response"
)

const (
	tplRegister = "register.html.tpl"
)

// RegisterStorer must be implemented in order to satisfy the register module's
// storage requirments.
type RegisterStorer interface {
	authboss.Storer
	// Create is the same as put, except it refers to a non-existent key.
	Create(key string, attr authboss.Attributes) error
}

func init() {
	authboss.RegisterModule("register", &Register{})
}

// Register module.
type Register struct {
	*authboss.Authboss
	templates response.Templates
}

// Initialize the module.
func (r *Register) Initialize(ab *authboss.Authboss) (err error) {
	r.Authboss = ab

	if r.Storer == nil {
		return errors.New("register: Need a RegisterStorer")
	}

	if _, ok := r.Storer.(RegisterStorer); !ok {
		return errors.New("register: RegisterStorer required for register functionality")
	}

	if r.templates, err = response.LoadTemplates(r.Authboss, r.Layout, r.ViewsPath, tplRegister); err != nil {
		return err
	}

	return nil
}

// Routes creates the routing table.
func (r *Register) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/register": r.registerHandler,
	}
}

// Storage returns storage requirements.
func (r *Register) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		r.PrimaryID:            authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (reg *Register) registerHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		data := authboss.HTMLData{
			"primaryID":      reg.PrimaryID,
			"primaryIDValue": "",
		}
		return reg.templates.Render(ctx, w, r, tplRegister, data)
	case "POST":
		return reg.registerPostHandler(ctx, w, r)
	}
	return nil
}

func (reg *Register) registerPostHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	key, _ := ctx.FirstPostFormValue(reg.PrimaryID)
	password, _ := ctx.FirstPostFormValue(authboss.StorePassword)

	validationErrs := ctx.Validate(reg.Policies, reg.ConfirmFields...)

	if len(validationErrs) != 0 {
		data := authboss.HTMLData{
			"primaryID":      reg.PrimaryID,
			"primaryIDValue": key,
			"errs":           validationErrs.Map(),
		}

		return reg.templates.Render(ctx, w, r, tplRegister, data)
	}

	attr, err := ctx.Attributes() // Attributes from overriden forms
	if err != nil {
		return err
	}

	pass, err := bcrypt.GenerateFromPassword([]byte(password), reg.BCryptCost)
	if err != nil {
		return err
	}

	attr[reg.PrimaryID] = key
	attr[authboss.StorePassword] = string(pass)
	ctx.User = attr

	if err := reg.Storer.(RegisterStorer).Create(key, attr); err != nil {
		return err
	}

	if err := reg.Callbacks.FireAfter(authboss.EventRegister, ctx); err != nil {
		return err
	}

	if reg.IsLoaded("confirm") {
		response.Redirect(ctx, w, r, reg.RegisterOKPath, "Account successfully created, please verify your e-mail address.", "", true)
		return nil
	}

	ctx.SessionStorer.Put(authboss.SessionKey, key)
	response.Redirect(ctx, w, r, reg.RegisterOKPath, "Account successfully created, you are now logged in.", "", true)

	return nil
}
