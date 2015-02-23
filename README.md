<img src="http://i.imgur.com/fPIgqLg.jpg"/>

Authboss
========
Authboss is a modular authentication system for the web. It tries to remove as much boilerplate and "hard things" as possible so that each time you start a new web project in Go, you can plug it in, configure and be off to the races without having to think about the hard questions like how to store Remember Me tokens, or passwords.

Modules
========
Each module can be turned on simply by importing it and the side-effects take care of the rest. However each module has storage requirements and configuration that's required.

Name           | Import Path                                                                                         | Description
---------------|-----------------------------------------------------------------------------------------------------|------------
Core           | [gopkg.in/authboss.v0](https://github.com/go-authboss/authboss)                                     | Support for the modular system, constants, helpers.
Register       | [gopkg.in/authboss.v0/register](https://github.com/go-authboss/authboss/tree/master/register)       | Provides a registration section for users.
Confirm        | [gopkg.in/authboss.v0/confirm](https://github.com/go-authboss/authboss/tree/master/confirm)         | Sends an e-mail verification before allowing users to log in.
Recover        | [gopkg.in/authboss.v0/recover](https://github.com/go-authboss/authboss/tree/master/recover)         | Allows for password resets via e-mail.
Remember       | [gopkg.in/authboss.v0/remember](https://github.com/go-authboss/authboss/tree/master/remember)       | Persisting login sessions past session expiry.
Lock           | [gopkg.in/authboss.v0/lock](https://github.com/go-authboss/authboss/tree/master/lock)               | Locks user accounts after N authentication failures in M time.
Expire         | [gopkg.in/authboss.v0/expire](https://github.com/go-authboss/authboss/tree/master/expire)           | Expires user sessions after a certain period of inactivity.
