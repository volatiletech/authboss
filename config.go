package authboss

// Config is a map to provide configuration key-values.
//
type Config struct {
	MountPath string `json:"mountPath" xml:"mountPath"`

	AuthLoginPageURI   string `json:"authLoginPage" xml:"authLoginPage"`
	AuthLogoutRedirect string `json:"authLogoutRedirect" xml:"authLogoutRedirect"`
}

func NewConfig() {

}
