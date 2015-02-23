package recover

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/render"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin           = "login.tpl"
	tplRecover         = "recover.tpl"
	tplRecoverComplete = "recover-complete.tpl"
	tplInitHTMLEmail   = "recover-html.email"
	tplInitTextEmail   = "recover-text.email"

	storeUsername           = "username"
	storeRecoverToken       = "recover_token"
	storeRecoverTokenExpiry = "recover_token_expiry"
	storeEmail              = "email"
	storePassword           = "password"
)

var errRecoveryTokenExpired = errors.New("recovery token expired")

func init() {
	m := &Recover{}
	authboss.RegisterModule("recover", m)
}

type Recover struct {
	templates      render.Templates
	emailTemplates render.Templates
}

func (r *Recover) Initialize() (err error) {
	if authboss.Cfg.Storer == nil {
		return errors.New("recover: Need a RecoverStorer.")
	}

	if _, ok := authboss.Cfg.Storer.(authboss.RecoverStorer); !ok {
		return errors.New("recover: RecoverStorer required for recover functionality.")
	}

	r.templates, err = render.LoadTemplates(authboss.Cfg.Layout, authboss.Cfg.ViewsPath, tplRecover, tplRecoverComplete)
	if err != nil {
		return err
	}

	r.emailTemplates, err = render.LoadTemplates(authboss.Cfg.LayoutEmail, authboss.Cfg.ViewsPath, tplInitHTMLEmail, tplInitTextEmail)
	if err != nil {
		return err
	}

	return nil
}

func (r *Recover) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"recover":          r.startHandlerFunc,
		"recover/complete": r.completeHandlerFunc,
	}
}
func (r *Recover) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		storeUsername:           authboss.String,
		storeRecoverToken:       authboss.String,
		storeEmail:              authboss.String,
		storeRecoverTokenExpiry: authboss.String,
		storePassword:           authboss.String,
	}
}

func (r *Recover) startHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	case methodGET:
		data := authboss.NewHTMLData(
			"primaryID", authboss.Cfg.PrimaryID,
			"primaryIDValue", "",
			"confirmPrimaryIDValue", "",
		)

		return r.templates.Render(ctx, w, req, tplRecover, data)
	case methodPOST:
		primaryID, _ := ctx.FirstPostFormValue(authboss.Cfg.PrimaryID)
		confirmPrimaryID, _ := ctx.FirstPostFormValue(fmt.Sprintf("confirm_%s", authboss.Cfg.PrimaryID))

		errData := authboss.NewHTMLData(
			"primaryID", authboss.Cfg.PrimaryID,
			"primaryIDValue", primaryID,
			"confirmPrimaryIDValue", confirmPrimaryID,
		)

		policies := authboss.FilterValidators(authboss.Cfg.Policies, authboss.Cfg.PrimaryID)
		if validationErrs := ctx.Validate(policies, authboss.Cfg.ConfirmFields...).Map(); len(validationErrs) > 0 {
			fmt.Fprintln(authboss.Cfg.LogWriter, "recover: form validation failed:", validationErrs)
			errData.MergeKV("errs", validationErrs)
			return r.templates.Render(ctx, w, req, tplRecover, errData)
		}

		if err := ctx.LoadUser(primaryID); err == authboss.ErrUserNotFound {
			errData.MergeKV("flashError", authboss.Cfg.RecoverFailedErrorFlash)
			return r.templates.Render(ctx, w, req, tplRecover, errData)
		} else if err != nil {
			return err
		}

		email, err := ctx.User.StringErr(storeEmail)
		if err != nil {
			return err
		}

		encodedToken, encodedChecksum, err := newToken()
		if err != nil {
			return err
		}

		ctx.User[storeRecoverToken] = encodedChecksum
		ctx.User[storeRecoverTokenExpiry] = time.Now().Add(authboss.Cfg.RecoverTokenDuration)

		if err := ctx.SaveUser(); err != nil {
			return err
		}

		go goRecoverEmail(r, email, encodedToken)

		ctx.SessionStorer.Put(authboss.FlashSuccessKey, authboss.Cfg.RecoverInitiateSuccessFlash)
		http.Redirect(w, req, authboss.Cfg.RecoverRedirect, http.StatusFound)
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
	url := fmt.Sprintf("%s/recover/complete?token=%s", authboss.Cfg.HostName, encodedToken)

	email := authboss.Email{
		To:      []string{to},
		From:    authboss.Cfg.EmailFrom,
		Subject: authboss.Cfg.EmailSubjectPrefix + "Password Reset",
	}

	if err := r.emailTemplates.RenderEmail(email, tplInitHTMLEmail, tplInitTextEmail, url); err != nil {
		fmt.Fprintln(authboss.Cfg.LogWriter, "recover: failed to send recover email:", err)
	}
}

func (r *Recover) completeHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, req *http.Request) (err error) {
	switch req.Method {
	case methodGET:
		_, err = verifyToken(ctx)
		if err == errRecoveryTokenExpired {
			return authboss.ErrAndRedirect{err, "/recover", "", authboss.Cfg.RecoverTokenExpiredFlash}
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

		policies := authboss.FilterValidators(authboss.Cfg.Policies, "password")
		if validationErrs := ctx.Validate(policies, authboss.Cfg.ConfirmFields...).Map(); len(validationErrs) > 0 {
			fmt.Fprintln(authboss.Cfg.LogWriter, "recover: form validation failed:", validationErrs)
			data := authboss.NewHTMLData(
				"token", token,
				"password", password,
				"confirmPassword", confirmPassword,
				"errs", validationErrs,
			)
			return r.templates.Render(ctx, w, req, tplRecoverComplete, data)
		}

		if ctx.User, err = verifyToken(ctx); err != nil {
			return err
		}

		encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), authboss.Cfg.BCryptCost)
		if err != nil {
			return err
		}

		ctx.User[storePassword] = string(encryptedPassword)
		ctx.User[storeRecoverToken] = ""
		var nullTime time.Time
		ctx.User[storeRecoverTokenExpiry] = nullTime

		primaryID, err := ctx.User.StringErr(authboss.Cfg.PrimaryID)
		if err != nil {
			return err
		}

		if err := ctx.SaveUser(); err != nil {
			return err
		}

		ctx.SessionStorer.Put(authboss.SessionKey, primaryID)
		http.Redirect(w, req, authboss.Cfg.AuthLoginSuccessRoute, http.StatusFound)
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
	storer := authboss.Cfg.Storer.(authboss.RecoverStorer)

	userInter, err := storer.RecoverUser(base64.StdEncoding.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}

	attrs = authboss.Unbind(userInter)

	expiry, ok := attrs.DateTime(storeRecoverTokenExpiry)
	if !ok || time.Now().After(expiry) {
		return nil, errRecoveryTokenExpired
	}

	return attrs, nil
}
