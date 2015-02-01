package flashutil

import "gopkg.in/authboss.v0"

// Pull is a convenience func to retreive then delete a flash message.  Any ok
// checks are ignored as they don't alter the intended use.
func Pull(storer authboss.ClientStorer, key string) string {
	value, _ := storer.Get(key)
	storer.Del(key)
	return value
}
