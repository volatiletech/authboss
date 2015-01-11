package authboss

// ClientStorer should be able to store values on the clients machine. This is
// usually going to be a cookie store.
type ClientStorer interface {
	Put(key, value string)
	Get(key string) string
}
