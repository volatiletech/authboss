# App Requirements

Authboss does a lot of things, but it doesn't do some of the important things that are required by
a typical authentication system, because it can't guarantee that you're doing many of those things
in a different way already, so it punts the responsibility.

### CSRF Protection

What this means is you should apply a middleware that can protect the application from csrf
attacks or you may be vulnerable. Authboss previously handled this but it took on a dependency
that was unnecessary and it complicated the code. Because Authboss does not render views nor
consumes data directly from the user, it no longer does this.

### Request Throttling

Currently Authboss is vulnerable to brute force attacks because there are no protections on
it's endpoints. This again is left up to the creator of the website to protect the whole website
at once (as well as Authboss) from these sorts of attacks.
