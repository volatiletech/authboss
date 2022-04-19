package authboss

type CredsGenerator interface {
	// GenerateCreds generates pieces needed as credentials
	// selector: to be stored in the database and used in SELECT query
	// verifier: to be stored in database but never used in SELECT query
	// token: the user-facing base64 encoded selector+verifier
	GenerateCreds() (selector, verifier, token string, err error)

	ParseToken(token string) (selectorBytes, verifierBytes []byte)

	TokenSize() int
}
