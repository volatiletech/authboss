package recover

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/flashutil"
)

var errRecoveryTokenExpired = errors.New("recovery token expired")

type pageRecoverComplete struct {
	Token, Password, ConfirmPassword string
	ErrMap                           map[string][]string
	FlashSuccess, FlashError         string
}

func (m *RecoverModule) recoverCompleteHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		_, err := verifyToken(ctx, authboss.Cfg.Storer.(authboss.RecoverStorer))
		if err != nil {
			if err.Error() == errRecoveryTokenExpired.Error() {
				fmt.Fprintln(authboss.Cfg.LogWriter, "recover [token expired]:", err)
				ctx.SessionStorer.Put(authboss.FlashErrorKey, authboss.Cfg.RecoverTokenExpiredFlash)
				http.Redirect(w, r, "/recover", http.StatusFound)
				return
			} else {
				fmt.Fprintln(authboss.Cfg.LogWriter, "recover:", err)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}

		token, _ := ctx.FirstFormValue("token")

		page := pageRecoverComplete{
			Token:      token,
			FlashError: flashutil.Pull(ctx.SessionStorer, authboss.FlashErrorKey),
		}
		m.execTpl(tplRecoverComplete, w, page)
	case methodPOST:
		errPage := m.recoverComplete(ctx)
		if errPage != nil {
			m.execTpl(tplRecoverComplete, w, *errPage)
			return
		}

		http.Redirect(w, r, authboss.Cfg.AuthLoginSuccessRoute, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// verifyToken expects a base64.URLEncoded token.
func verifyToken(ctx *authboss.Context, storer authboss.RecoverStorer) (attrs authboss.Attributes, err error) {
	token, ok := ctx.FirstFormValue("token")
	if !ok {
		return nil, errors.New("missing form value: token")
	}

	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	sum := md5.Sum(decoded)
	userInter, err := storer.RecoverUser(base64.StdEncoding.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}

	attrs = authboss.Unbind(userInter)

	expiry, ok := attrs.DateTime(attrRecoverTokenExpiry)
	if !ok || time.Now().After(expiry) {
		return nil, errRecoveryTokenExpired
	}

	return attrs, nil
}

func (m *RecoverModule) recoverComplete(ctx *authboss.Context) (errPage *pageRecoverComplete) {
	token, _ := ctx.FirstFormValue("token")
	password, _ := ctx.FirstPostFormValue("password")
	confirmPassword, _ := ctx.FirstPostFormValue("confirmPassword")
	defaultErrPage := &pageRecoverComplete{token, password, confirmPassword, nil, "", authboss.Cfg.RecoverFailedErrorFlash}

	var err error
	ctx.User, err = verifyToken(ctx, authboss.Cfg.Storer.(authboss.RecoverStorer))
	if err != nil {
		fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "failed to verify token", err)
		return defaultErrPage
	}

	policies := authboss.FilterValidators(authboss.Cfg.Policies, "password")
	if validationErrs := ctx.Validate(policies, authboss.Cfg.ConfirmFields...); len(validationErrs) > 0 {
		fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "validation failed", validationErrs)
		return &pageRecoverComplete{token, password, confirmPassword, validationErrs.Map(), "", ""}
	}

	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), authboss.Cfg.BCryptCost)
	if err != nil {
		fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "failed to encrypt password", err)
		return defaultErrPage
	}
	ctx.User[attrPassword] = string(encryptedPassword)
	ctx.User[attrRecoverToken] = ""
	var nullTime time.Time
	ctx.User[attrRecoverTokenExpiry] = nullTime

	username, _ := ctx.User.String(attrUsername)
	if err := ctx.SaveUser(username, authboss.Cfg.Storer); err != nil {
		fmt.Fprintf(authboss.Cfg.LogWriter, errFormat, "failed to save user", err)
		return defaultErrPage
	}

	ctx.SessionStorer.Put(authboss.SessionKey, username)
	return nil
}
