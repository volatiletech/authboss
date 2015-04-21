// Package recover implements password reset via e-mail.
package recover

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/response"
)

// Storage constants
const (
	StoreRecoverToken       = "recover_token"
	StoreRecoverTokenExpiry = "recover_token_expiry"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin           = "login.html.tpl"
	tplRecover         = "recover.html.tpl"
	tplRecoverComplete = "recover_complete.html.tpl"
	tplInitHTMLEmail   = "recover_email.html.tpl"
	tplInitTextEmail   = "recover_email.txt.tpl"

	recoverInitiateSuccessFlash = "An email has been sent with further instructions on how to reset your password"
	recoverTokenExpiredFlash    = "Account recovery request has expired. Please try again."
	recoverFailedErrorFlash     = "Account recovery has failed. Please contact tech support."
)

var errRecoveryTokenExpired = errors.New("recovery token expired")

// RecoverStorer must be implemented in order to satisfy the recover module's
// storage requirements.
type RecoverStorer interface {
	authboss.Storer
	// RecoverUser looks a user up by a recover token. See recover module for
	// attribute names. If the key is not found in the data store,
	// simply return nil, ErrUserNotFound.
	RecoverUser(recoverToken string) (interface{}, error)
}

func init() {
	m := &Recover{}
	authboss.RegisterModule("recover", m)
}

// Recover module
type Recover struct {
	*authboss.Authboss
	templates          response.Templates
	emailHTMLTemplates response.Templates
	emailTextTemplates response.Templates
}

// Initialize module
func (r *Recover) Initialize(ab *authboss.Authboss) (err error) {
	r.Authboss = ab

	if r.Storer == nil {
		return errors.New("recover: Need a RecoverStorer")
	}

	if _, ok := r.Storer.(RecoverStorer); !ok {
		return errors.New("recover: RecoverStorer required for recover functionality")
	}

	if len(r.XSRFName) == 0 {
		return errors.New("auth: XSRFName must be set")
	}

	if r.XSRFMaker == nil {
		return errors.New("auth: XSRFMaker must be defined")
	}

	r.templates, err = response.LoadTemplates(r.Authboss, r.Layout, r.ViewsPath, tplRecover, tplRecoverComplete)
	if err != nil {
		return err
	}

	r.emailHTMLTemplates, err = response.LoadTemplates(r.Authboss, r.LayoutHTMLEmail, r.ViewsPath, tplInitHTMLEmail)
	if err != nil {
		return err
	}
	r.emailTextTemplates, err = response.LoadTemplates(r.Authboss, r.LayoutTextEmail, r.ViewsPath, tplInitTextEmail)
	if err != nil {
		return err
	}

	return nil
}

// Routes for module
func (r *Recover) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/recover":          r.startHandlerFunc,
		"/recover/complete": r.completeHandlerFunc,
	}
}

// Storage requirements
func (r *Recover) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		r.PrimaryID:             authboss.String,
		authboss.StoreEmail:     authboss.String,
		authboss.StorePassword:  authboss.String,
		StoreRecoverToken:       authboss.String,
		StoreRecoverTokenExpiry: authboss.String,
	}
}

func (rec *Recover) startHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		data := authboss.NewHTMLData(
			"primaryID", rec.PrimaryID,
			"primaryIDValue", "",
			"confirmPrimaryIDValue", "",
		)

		return rec.templates.Render(ctx, w, r, tplRecover, data)
	case methodPOST:
		primaryID, _ := ctx.FirstPostFormValue(rec.PrimaryID)
		confirmPrimaryID, _ := ctx.FirstPostFormValue(fmt.Sprintf("confirm_%s", rec.PrimaryID))

		errData := authboss.NewHTMLData(
			"primaryID", rec.PrimaryID,
			"primaryIDValue", primaryID,
			"confirmPrimaryIDValue", confirmPrimaryID,
		)

		policies := authboss.FilterValidators(rec.Policies, rec.PrimaryID)
		if validationErrs := ctx.Validate(policies, rec.PrimaryID, authboss.ConfirmPrefix+rec.PrimaryID).Map(); len(validationErrs) > 0 {
			errData.MergeKV("errs", validationErrs)
			return rec.templates.Render(ctx, w, r, tplRecover, errData)
		}

		// redirect to login when user not found to prevent username sniffing
		if err := ctx.LoadUser(primaryID); err == authboss.ErrUserNotFound {
			return authboss.ErrAndRedirect{err, rec.RecoverOKPath, recoverInitiateSuccessFlash, ""}
		} else if err != nil {
			return err
		}

		email, err := ctx.User.StringErr(authboss.StoreEmail)
		if err != nil {
			return err
		}

		encodedToken, encodedChecksum, err := newToken()
		if err != nil {
			return err
		}

		ctx.User[StoreRecoverToken] = encodedChecksum
		ctx.User[StoreRecoverTokenExpiry] = time.Now().Add(rec.RecoverTokenDuration)

		if err := ctx.SaveUser(); err != nil {
			return err
		}

		goRecoverEmail(rec, email, encodedToken)

		ctx.SessionStorer.Put(authboss.FlashSuccessKey, recoverInitiateSuccessFlash)
		response.Redirect(ctx, w, r, rec.RecoverOKPath, "", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

func newToken() (encodedToken, encodedChecksum string, err error) {
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return "", "", err
	}
	sum := md5.Sum(token)

	return base64.URLEncoding.EncodeToString(token), base64.StdEncoding.EncodeToString(sum[:]), nil
}

var goRecoverEmail = func(r *Recover, to, encodedToken string) {
	go r.sendRecoverEmail(to, encodedToken)
}

func (r *Recover) sendRecoverEmail(to, encodedToken string) {
	p := path.Join(r.MountPath, "recover/complete")
	url := fmt.Sprintf("%s%s?token=%s", r.RootURL, p, encodedToken)

	email := authboss.Email{
		To:      []string{to},
		From:    r.EmailFrom,
		Subject: r.EmailSubjectPrefix + "Password Reset",
	}

	if err := response.Email(r.Mailer, email, r.emailHTMLTemplates, tplInitHTMLEmail, r.emailTextTemplates, tplInitTextEmail, url); err != nil {
		fmt.Fprintln(r.LogWriter, "recover: failed to send recover email:", err)
	}
}

func (r *Recover) completeHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, req *http.Request) (err error) {
	switch req.Method {
	case methodGET:
		_, err = verifyToken(ctx)
		if err == errRecoveryTokenExpired {
			return authboss.ErrAndRedirect{err, "/recover", "", recoverTokenExpiredFlash}
		} else if err != nil {
			return authboss.ErrAndRedirect{err, "/", "", ""}
		}

		token, _ := ctx.FirstFormValue("token")
		data := authboss.NewHTMLData("token", token)
		return r.templates.Render(ctx, w, req, tplRecoverComplete, data)
	case methodPOST:
		token, err := ctx.FirstFormValueErr("token")
		if err != nil {
			return err
		}

		password, _ := ctx.FirstPostFormValue("password")
		confirmPassword, _ := ctx.FirstPostFormValue("confirmPassword")

		policies := authboss.FilterValidators(r.Policies, "password")
		if validationErrs := ctx.Validate(policies, authboss.StorePassword, authboss.ConfirmPrefix+authboss.StorePassword).Map(); len(validationErrs) > 0 {
			data := authboss.NewHTMLData(
				"token", token,
				"errs", validationErrs,
			)
			return r.templates.Render(ctx, w, req, tplRecoverComplete, data)
		}

		if ctx.User, err = verifyToken(ctx); err != nil {
			return err
		}

		encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), r.BCryptCost)
		if err != nil {
			return err
		}

		ctx.User[authboss.StorePassword] = string(encryptedPassword)
		ctx.User[StoreRecoverToken] = ""
		var nullTime time.Time
		ctx.User[StoreRecoverTokenExpiry] = nullTime

		primaryID, err := ctx.User.StringErr(r.PrimaryID)
		if err != nil {
			return err
		}

		if err := ctx.SaveUser(); err != nil {
			return err
		}

		if err := r.Callbacks.FireAfter(authboss.EventPasswordReset, ctx); err != nil {
			return err
		}

		ctx.SessionStorer.Put(authboss.SessionKey, primaryID)
		response.Redirect(ctx, w, req, r.AuthLoginOKPath, "", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

// verifyToken expects a base64.URLEncoded token.
func verifyToken(ctx *authboss.Context) (attrs authboss.Attributes, err error) {
	token, err := ctx.FirstFormValueErr("token")
	if err != nil {
		return nil, err
	}

	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	sum := md5.Sum(decoded)
	storer := ctx.Storer.(RecoverStorer)

	userInter, err := storer.RecoverUser(base64.StdEncoding.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}

	attrs = authboss.Unbind(userInter)

	expiry, ok := attrs.DateTime(StoreRecoverTokenExpiry)
	if !ok || time.Now().After(expiry) {
		return nil, errRecoveryTokenExpired
	}

	return attrs, nil
}
