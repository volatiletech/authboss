package authboss

type Hasher interface {
	GenerateHash(s string) (string, error)
}
