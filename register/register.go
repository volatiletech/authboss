// Package register allows for user registration.
package register

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/render"
)

const (
	tplRegister = "register.html.tpl"
)

// R is the singleton instance of the register module which will have been
// configured and ready to use after authboss.Init()
var R *Register

func init() {
	R = &Register{}
	authboss.RegisterModule("register", R)
}

// Register module.
type Register struct {
	templates render.Templates
}

// Initialize the module.
func (r *Register) Initialize() (err error) {
	if r.templates, err = render.LoadTemplates(authboss.Cfg.Layout, authboss.Cfg.ViewsPath, tplRegister); err != nil {
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
		authboss.Cfg.PrimaryID: authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (reg *Register) registerHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		data := authboss.HTMLData{
			"primaryID":      authboss.Cfg.PrimaryID,
			"primaryIDValue": "",
		}
		return reg.templates.Render(ctx, w, r, tplRegister, data)
	case "POST":
		return reg.registerPostHandler(ctx, w, r)
	}
	return nil
}

func (reg *Register) registerPostHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	key, _ := ctx.FirstPostFormValue(authboss.Cfg.PrimaryID)
	password, _ := ctx.FirstPostFormValue(authboss.StorePassword)

	policies := authboss.FilterValidators(authboss.Cfg.Policies, authboss.Cfg.PrimaryID, authboss.StorePassword)
	validationErrs := ctx.Validate(policies, authboss.Cfg.ConfirmFields...)

	if len(validationErrs) != 0 {
		data := authboss.HTMLData{
			"primaryID":      authboss.Cfg.PrimaryID,
			"primaryIDValue": key,
			"errs":           validationErrs.Map(),
		}

		return reg.templates.Render(ctx, w, r, tplRegister, data)
	}

	attr, err := ctx.Attributes() // Attributes from overriden forms
	if err != nil {
		return err
	}

	pass, err := bcrypt.GenerateFromPassword([]byte(password), authboss.Cfg.BCryptCost)
	if err != nil {
		return err
	}

	attr[authboss.Cfg.PrimaryID] = key
	attr[authboss.StorePassword] = string(pass)
	delete(attr, authboss.ConfirmPrefix+authboss.StorePassword)
	ctx.User = attr

	if err := authboss.Cfg.Storer.Create(key, attr); err != nil {
		return err
	}

	authboss.Cfg.Callbacks.FireAfter(authboss.EventRegister, ctx)

	if authboss.IsLoaded("confirm") {
		render.Redirect(ctx, w, r, "/", "Account successfully created, please verify your e-mail address.", "")
		return nil
	}

	ctx.SessionStorer.Put(authboss.SessionKey, key)
	render.Redirect(ctx, w, r, "/", "Account successfully created, you are now logged in.", "")

	return nil
}
