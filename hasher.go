package authboss

type Hasher interface {
	CompareHashAndPassword(string, string) error
	GenerateHash(s string) (string, error)
}
