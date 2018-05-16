<img src="http://i.imgur.com/fPIgqLg.jpg"/>

<!-- TOC -->

- [Authboss](#authboss)
- [Why use Authboss?](#why-use-authboss)
- [Getting Started](#getting-started)
    - [App Requirements](#app-requirements)
        - [CSRF Protection](#csrf-protection)
        - [Request Throttling](#request-throttling)
    - [Integration Requirements](#integration-requirements)
        - [Middleware](#middleware)
        - [Configuration](#configuration)
        - [Storage and Core implementations](#storage-and-core-implementations)
        - [ServerStorer implementation](#serverstorer-implementation)
        - [User implementation](#user-implementation)
        - [Values implementation](#values-implementation)
    - [Config](#config)
        - [Paths](#paths)
        - [Modules](#modules)
        - [Mail](#mail)
        - [Storage](#storage)
        - [Core](#core)
- [Available Modules](#available-modules)
- [Middlewares](#middlewares)
- [Use Cases](#use-cases)
    - [Get Current User](#get-current-user)
    - [Reset Password](#reset-password)
    - [User Auth via Password](#user-auth-via-password)
    - [User Auth via OAuth2](#user-auth-via-oauth2)
    - [User Registration](#user-registration)
    - [Confirming Registrations](#confirming-registrations)
    - [Password Recovery](#password-recovery)
    - [Remember Me](#remember-me)
    - [Locking Users](#locking-users)
    - [Expiring User Sessions](#expiring-user-sessions)
    - [Rendering Views](#rendering-views)
        - [HTML Views](#html-views)
        - [JSON Views](#json-views)
        - [Data](#data)

<!-- /TOC -->

# Authboss

[![GoDoc](https://godoc.org/github.com/volatiletech/authboss?status.svg)](https://godoc.org/github.com/volatiletech/authboss)
[![Build Status](https://circleci.com/gh/volatiletech/authboss.svg?style=shield&circle-token=:circle-token)](https://circleci.com/gh/volatiletech/authboss)
[![Coverage Status](https://coveralls.io/repos/volatiletech/authboss/badge.svg?branch=master)](https://coveralls.io/r/volatiletech/authboss?branch=master)
[![Mail](https://img.shields.io/badge/mail%20list-authboss-lightgrey.svg)](https://groups.google.com/a/volatile.tech/forum/#!forum/authboss)

Authboss is a modular authentication system for the web.

It has several modules that represent authentication and authorization features that are common
to websites in general so that you can enable as many as you need, and leave the others out.
It makes it easy to plug in authentication to an application and get a lot of functionality
for (hopefully) a smaller amount of integration effort.

# Why use Authboss?

Every time you'd like to start a new web project, you really want to get to the heart of what you're
trying to accomplish very quickly and it would be a sure bet to say one of the systems you're excited
about implementing and innovating on is not authentication. In fact it's very much the opposite: it's
one of those things that you have to do and one of those things you loathe to do. Authboss is supposed
to remove a lot of the tedium that comes with this, as well as a lot of the chances to make mistakes.
This allows you to care about what you're intending to do, rather than on ancillary support systems
to make it happen.

Here are a few bullet point reasons you might like to try it out:

* Saves you time (Authboss integration time should be less than re-implementation time)
* Saves you mistakes (at least using Authboss, people can bug fix as a collective and all benefit)
* Should integrate with or without any web framework

# Getting Started

To get started with Authboss in the simplest way, is to simply create a Config, populate it
with the things that are required, and start implementing [use cases](#use-cases). The use
cases describe what's required to be able to be able to use a particular piece of functionality,
or the best practice when implementing a piece of functionality. Please note the
[app requirements](#app-requirements) for your application as well
[integration requirements](#integration-requirements) that follow.

Of course the standard practice of fetching the library is just the beginning:

```bash
# Get the latest, keep in mind you should be vendoring with dep or using vgo at this point
# To ensure versions don't get messed up underneath you
go get -u github.com/volatiletech/authboss
```

Here's a bit of starter code that was stolen from the sample.

```go
ab := authboss.New()

ab.Config.Storage.Server = myDatabaseImplementation
ab.Config.Storage.SessionState = mySessionImplementation
ab.Config.Storage.CookieState = myCookieImplementation

ab.Config.Paths.Mount = "/authboss"
ab.Config.Paths.RootURL = "https://www.example.com/"

// This is using the renderer from: github.com/volatiletech/authboss
ab.Config.Core.ViewRenderer = abrenderer.New("/auth")
// Probably want a MailRenderer here too.

// Set up defaults for basically everything besides the ViewRenderer/MailRenderer in the HTTP stack
defaults.SetCore(&ab.Config, false)

if err := ab.Init(); err != nil {
    panic(err)
}

// Mount the router to a path (this should be the same as the Mount path above)
// mux in this example is a chi router, but it could be anything that can route to
// the Core.Router.
mux.Mount("/authboss", http.StripPrefix("/authboss", ab.Config.Core.Router))

```

For a more in-depth look you **definitely should** look at the authboss sample to see what a full 
implementation looks like. This will probably help you more than any of this documentation.

[https://github.com/volatiletech/authboss-sample](https://github.com/volatiletech/authboss-sample)

## App Requirements

Authboss does a lot of things, but it doesn't do some of the important things that are required by
a typical authentication system, because it can't guarantee that you're doing many of those things
in a different way already, so it punts the responsibility.

### CSRF Protection

What this means is you should apply a middleware that can protect the application from crsf
attacks or you may be vulnerable. Authboss previously handled this but it took on a dependency
that was unnecessary and it complicated the code. Because Authboss does not render views nor
consumes data directly from the user, it no longer does this.

### Request Throttling

Currently Authboss is vulnerable to brute force attacks because there are no protections on
it's endpoints. This again is left up to the creator of the website to protect the whole website
at once (as well as Authboss) from these sorts of attacks.

## Integration Requirements

In terms of integrating Authboss into your app, the following things must be considered.

### Middleware

There are middlewares that are required to be installed in your middleware stack if it's
all to function properly, please see [Middlewares](#Middlewares) for more information.

### Configuration

There are some required configuration variables that have no sane defaults:

* Config.Paths.Mount
* Config.Paths.RootURL

### Storage and Core implementations

Everything under Config.Storage and Config.Core are required. however you can optionally use default
implementations from the [defaults package](https://github.com/volatiletech/authboss/defaults).
This also provides an easy way to share implementations of certain stack pieces (like HTML Form Parsing).
As you see in the example above these can be easily initialized with the `SetCore` method in that
package.

The following is a list of storage interfaces, they must be provided by the implementer. Server is a
very involved implementation, please see the additional documentation below for more details.

* Config.Storage.Server
* Config.Storage.SessionState
* Config.Storage.CookieState (only for remember me)

The following is a list of the core pieces, these typically are abstracting the HTTP stack.
Out of all of these you'll probably be mostly okay with the default implementations in the
defaults package but there are two big exceptions to this rule and that's the ViewRenderer
and the MailRenderer. For more information please see the use case [Rendering Views](#rendering-views)

* Config.Core.Router
* Config.Core.ErrorHandler
* Config.Core.Responder
* Config.Core.Redirector
* Config.Core.BodyReader
* Config.Core.ViewRenderer
* Config.Core.MailRenderer
* Config.Core.Mailer
* Config.Core.Logger

### ServerStorer implementation

The [ServerStorer](https://godoc.org//github.com/volatiletech/authboss/#ServerStorer) is
meant to be upgraded to add capabilities depending on what modules you'd like to use.
It starts out by only knowing how to save and load users, but the `remember` module as an example
needs to be able to find users by remember me tokens, so it upgrades to a
[RememberingServerStorer](https://godoc.org/github.com/volatiletech/authboss/#RememberingServerStorer)
which adds these abilities.

Your `ServerStorer` implementation does not need to implement all these additional interfaces
unless you're using a module that requires it. See the [Use Cases](#use-cases) documentation to know what the requirements are.

### User implementation

Users in Authboss are represented by the
[User interface](https://godoc.org//github.com/volatiletech/authboss/#User). The user
interface is a flexible notion, because it can be upgraded to suit the needs of the various modules.

Initially the User must only be able to Get/Set a `PID` or primary identifier. This allows the authboss
modules to know how to refer to him in the database. The `ServerStorer` also makes use of this
to save/retrieve users.

As mentioned, it can be upgraded, for example suppose now we want to use the `confirm` module,
in that case the e-mail address now becomes a requirement. So the `confirm` module will attempt
to upgrade the user (and panic if it fails) to a
[ConfirmableUser](https://godoc.org//github.com/volatiletech/authboss/#ConfirmableUser)
which supports retrieving and setting of confirm tokens, e-mail addresses, and a confirmed state.

Your `User` implementation does not need to implement all these additional user interfaces unless you're
using a module that requires it. See the [Use Cases](#use-cases) documentation to know what the
requirements are.

### Values implementation

The [BodyReader](https://godoc.org//github.com/volatiletech/authboss/#BodyReader)
interface in the Config returns
[Validator](https://godoc.org//github.com/volatiletech/authboss/#Validator) implementations
which can be validated. But much like the storer and user it can be upgraded to add different
capabilities.

Typically the way this will look as an implementation is to check the page being requested, switch on that to parse the body in whatever way (msgpack, json, url-encoded, doesn't matter), and produce
a struct that has the ability to `Validate` it's data as well as functions to retrieve the data
necessary for the particular valuer required by the module.

Your body reader implementation does not need to implement all valuer types unless you're
using a module that requires it. See the [Use Cases](#use-cases) documentation to know what the
requirements are.

## Config

The config struct is an important part of Authboss. It's the key to making Authboss do what you
want with the implementations you want. Please look at it's code definition as you read the
documentation below, it will make much more sense.

[Config Struct Documentation](https://godoc.org/github.com/volatiletech/authboss/#Config)

### Paths

Paths are the paths that should be redirected to or used in whatever circumstance they describe.
Two special paths that are required are `Mount` and `RootURL`, without which certain authboss
modules will not function correctly.

### Modules

Modules are module specific configuration options. They mostly control the behavior of modules.
For example `RegisterPreserveFields` decides a whitelist of fields to allow back into the data
to be re-rendered so the user doesn't have to type them in again.

### Mail

Mail sending related options.

### Storage

These are the implementations of how storage on the server and the client are done in your
app. There are no default implementations for these at this time. See the Godoc for more information
about what these are.

### Core

These are the implementations of the HTTP stack for your app. How do responses render? How are
they redirected? How are errors handled?

For most of these there are default implementations implementations from the
[defaults package](https://github.com/volatiletech/authboss/defaults) available, but not for all.
See the package documentation for more information about what's available.

# Available Modules

Each module can be turned on simply by importing it and the side-effects take care of the rest.
Not all the capabilities of authboss are represented by a module, see [Use Cases](#use-cases)
to view the supported use cases as well as how to use them in your app.

Name     | Import Path                               | Description
---------|-------------------------------------------|------------
Auth     | github.com/volatiletech/authboss/auth     | Database password authentication for users.
Confirm  | github.com/volatiletech/authboss/confirm  | Prevents login before e-mail verification.
Expire   | github.com/volatiletech/authboss/expire   | Expires a user's login
Lock     | github.com/volatiletech/authboss/lock     | Locks user accounts after authentication failures.
Logout   | github.com/volatiletech/authboss/logout   | Destroys user sessions for auth/oauth2.
OAuth2   | github.com/volatiletech/authboss/oauth2   | Provides oauth2 authentication for users.
Recover  | github.com/volatiletech/authboss/recover  | Allows for password resets via e-mail.
Register | github.com/volatiletech/authboss/register | User-initiated account creation.
Remember | github.com/volatiletech/authboss/remember | Persisting login sessions past session cookie expiry.

# Middlewares

The only middleware that's truly required is the `LoadClientStateMiddleware`, and that's because it
enables session and cookie handling for Authboss. Without that, it's not a very useful piece of
software.

The remaining middlewares are either the implementation of an entire module (like expire),
or a key part of a module. For example you probably wouldn't want to use the lock module
without the middleware that would stop a locked user from using an authenticated resource,
because then locking wouldn't be useful unless of course you had your own way of dealing
with locking, which is why it's only recommended, and not required. Typically you will
use the middlewares if you use the module.

Name | Requirement | Description
---- | ----------- | -----------
[LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware) | **Required** | Enables cookie and session handling
[ModuleListMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.ModuleListMiddleware) | Optional | Inserts a loaded module list into the view data
[confirm.Middleware](https://godoc.org/github.com/volatiletech/authboss/confirm/#Middleware) | Recommended with confirm | Ensures users are confirmed or rejects request
[expire.Middleware](https://godoc.org/github.com/volatiletech/authboss/expire/#Middleware) | **Required** with expire | Expires user sessions after an inactive period
[lock.Middleware](https://godoc.org/github.com/volatiletech/authboss/lock/#Middleware) | Recommended with lock | Rejects requests from locked users
[remember.Middleware](https://godoc.org/github.com/volatiletech/authboss/remember/#Middleware) | Recommended with remember | Logs a user in from a remember cookie


# Use Cases

## Get Current User

CurrentUser can be retrieved by calling
[Authboss.CurrentUser](https://godoc.org/github.com/volatiletech/authboss/#Authboss.CurrentUser)
but a pre-requisite is that
[Authboss.LoadClientState](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientState)
has been called first to load the client state into the request context.
This is typically achieved by using the
[Authboss.LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware), but can
be done manually as well.

## Reset Password

Updating a user's password is non-trivial for several reasons:

1. The bcrypt algorithm must have the correct cost, and also be being used.
1. The user's remember me tokens should all be deleted so that previously authenticated sessions are invalid
1. Optionally the user should be logged out (**not taken care of by UpdatePassword**)

In order to do this, we can use the
[Authboss.UpdatePassword](https://godoc.org/github.com/volatiletech/authboss/#Authboss.UpdatePassword)
method. This ensures the above facets are taken care of.

If it's also desirable to have the user logged out, please use the following methods to erase
all known sessions and cookies from the user.

* [authboss.DelKnownSession](https://godoc.org//github.com/volatiletech/authboss/#DelKnownSession)
* [authboss.DelKnownCookie](https://godoc.org//github.com/volatiletech/authboss/#DelKnownCookie)

## User Auth via Password

| Info and Requirements |          |
| --------------------- | -------- |
Module        | auth
Pages         | login
Routes        | /login
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session and Cookie
ServerStorer  | [ServerStorer](https://godoc.org/github.com/volatiletech/authboss/#ServerStorer)
User          | [AuthableUser](https://godoc.org/github.com/volatiletech/authboss/#AuthableUser)
Values        | [UserValuer](https://godoc.org/github.com/volatiletech/authboss/#UserValuer)
Mailer        | _None_

To enable this side-effect import the auth module, and ensure that the requirements above are met.
It's very likely that you'd also want to enable the logout module in addition to this.

## User Auth via OAuth2

| Info and Requirements |          |
| --------------------- | -------- |
Module        | oauth2
Pages         | _None_
Routes        | /oauth2/{provider}, /oauth2/callback/{provider}
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [OAuth2ServerStorer](https://godoc.org/github.com/volatiletech/authboss/#OAuth2ServerStorer)
User          | [OAuth2User](https://godoc.org/github.com/volatiletech/authboss/#OAuth2User)
Values        | _None_
Mailer        | _None_

This is a tougher implementation than most modules because there's a lot going on. In addition to the
requirements stated above, you must also configure the `OAuth2Providers` in the config struct.

The providers require an oauth2 configuration that's typical for the Go oauth2 package, but in addition
to that they need a `FindUserDetails` method which has to take the token that's retrieved from the oauth2
provider, and call an endpoint that retrieves details about the user (at LEAST user's uid).
These parameters are returned in `map[string]string` form and passed into the `OAuth2ServerStorer`.

Please see the following documentation for more details:

* [Package docs for oauth2](https://godoc.org//github.com/volatiletech/authboss/oauth2/)
* [authboss.OAuth2Provider](https://godoc.org//github.com/volatiletech/authboss/#OAuth2Provider)
* [authboss.OAuth2ServerStorer](https://godoc.org//github.com/volatiletech/authboss/#OAuth2ServerStorer)

## User Registration

| Info and Requirements |          |
| --------------------- | -------- |
Module        | register
Pages         | register
Routes        | /register
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [CreatingServerStorer](https://godoc.org/github.com/volatiletech/authboss/#CreatingServerStorer)
User          | [AuthableUser](https://godoc.org/github.com/volatiletech/authboss/#AuthableUser), optionally [ArbitraryUser](https://godoc.org/github.com/volatiletech/authboss/#ArbitraryUser)
Values        | [UserValuer](https://godoc.org/github.com/volatiletech/authboss/#UserValuer), optionally also [ArbitraryValuer](https://godoc.org/github.com/volatiletech/authboss/#ArbitraryValuer)
Mailer        | _None_

Users can self-register for a service using this module. You may optionally want them to confirm
themselves, which can be done using the confirm module.

The complications in implementing registrations are around the `RegisterPreserveFields`. This is to
help in the case where a user fills out all these registration details, and then say enters a password
which doesn't mean minimum requirements and it fails during validation. These preserve fields should
stop the user from having to type in all that data again (it's a whitelist). This **must** be used
in conjuction with `ArbitraryValuer.GetValues()` and is described more on the configuration options
and the Valuer types themselves.

## Confirming Registrations

| Info and Requirements |          |
| --------------------- | -------- |
Module        | confirm
Pages         | confirm
Routes        | /confirm
Emails        | confirm_html, confirm_txt
Middlewares   | [LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware), [confirm.Middleware](https://godoc.org/github.com/volatiletech/authboss/confirm/#Middleware)
ClientStorage | Session
ServerStorer  | [ConfirmingServerStorer](https://godoc.org/github.com/volatiletech/authboss/#ConfirmingServerStorer)
User          | [ConfirmableUser](https://godoc.org/github.com/volatiletech/authboss/#ConfirmableUser)
Values        | [ConfirmValuer](https://godoc.org/github.com/volatiletech/authboss/#ConfirmValuer)
Mailer        | Required

Confirming registrations via e-mail can be done with this module (whether or not done via the register
module).

A hook on register kicks off the start of a confirmation which sends an e-mail with a token for the user.
When the user re-visits the page, the `BodyReader` must read the token and return a type that can
return the token.

Confirmations carry two values in the database to prevent a timing attack. The selector and the
verifier, always make sure in the ConfirmingServerStorer you're searching by the selector and
not the verifier.

## Password Recovery

| Info and Requirements |          |
| --------------------- | -------- |
Module        | recover
Pages         | recover_start, recover_middle (not used for renders, only values), recover_end
Routes        | /recover, /recover/end
Emails        | recover_html, recover_txt
Middlewares   | [LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [RecoveringServerStorer](https://godoc.org/github.com/volatiletech/authboss/#RecoveringServerStorer)
User          | [RecoverableUser](https://godoc.org/github.com/volatiletech/authboss/#RecoverableUser)
Values        | [RecoverStartValuer](https://godoc.org/github.com/volatiletech/authboss/#RecoverStartValuer), [RecoverMiddleValuer](https://godoc.org/github.com/volatiletech/authboss/#RecoverMiddleValuer), [RecoverEndValuer](https://godoc.org/github.com/volatiletech/authboss/#RecoverEndValuer)
Mailer        | Required

The flow for password recovery is that the user is initially shown a page that wants their `PID` to
be entered. The `RecoverStartValuer` retrieves that on `POST` to `/recover`.

An e-mail is sent out, and the user clicks the link inside it and is taken back to `/recover/end`
as a `GET`, at this point the `RecoverMiddleValuer` grabs the token and will insert it into the data
to be rendered.

They enter their password into the form, and `POST` to `/recover/end` which sends the token and
the new password which is retrieved by `RecoverEndValuer` which sets their password and saves them.

Password recovery has two values in the database to prevent a timing attack. The selector and the
verifier, always make sure in the RecoveringServerStorer you're searching by the selector and
not the verifier.

## Remember Me

| Info and Requirements |          |
| --------------------- | -------- |
Module        | remember
Pages         | _None_
Routes        | _None_
Emails        | _None_
Middlewares   | LoadClientStateMiddleware,
Middlewares   | [LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware), [remember.Middleware](https://godoc.org/github.com/volatiletech/authboss/remember/#Middleware)
ClientStorage | Session, Cookies
ServerStorer  | [RememberingServerStorer](https://godoc.org/github.com/volatiletech/authboss/#RememberingServerStorer)
User          | User
Values        | [RememberValuer](https://godoc.org/github.com/volatiletech/authboss/#RememberValuer) (not a Validator)
Mailer        | _None_

Remember uses cookie storage to log in users without a session via the `remember.Middleware`.
Because of this this middleware should be used high up in the stack, but it also needs to be after
the `LoadClientStateMiddleware` so that client state is available via the authboss mechanisms.

There is an intricacy to the `RememberingServerStorer`, it doesn't use the `User` struct at all,
instead it simply instructs the storer to save tokens to a pid and recall them just the same. Typically
in most databases this will require a separate table, though you could implement using pg arrays
or something as well.

A user who is logged in via Remember tokens is also considered "half-authed" which is a session
key that you can query to check to see if a user should have full rights to more sensitive data,
if they are half-authed and they want to change their user details for example you may want to
force them to go to the login screen and put in their password to get a full auth first.

## Locking Users

| Info and Requirements |          |
| --------------------- | -------- |
Module        | lock
Pages         | _None_
Routes        | _None_
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware), [lock.Middleware](https://godoc.org/github.com/volatiletech/authboss/lock/#Middleware)
ClientStorage | Session
ServerStorer  | [ServerStorer](https://godoc.org/github.com/volatiletech/authboss/#ServerStorer)
User          | [LockableUser](https://godoc.org/github.com/volatiletech/authboss/#LockableUser)
Values        | _None_
Mailer        | _None_

Lock ensures that a user's account becomes locked if authentication (both auth and oauth2) are
failed enough times.

The middleware protects resources from locked users, without it, there is no point to this module.
You should put in front of any resource that requires a login to function.

## Expiring User Sessions

| Info and Requirements |          |
| --------------------- | -------- |
Module        | expire
Pages         | _None_
Routes        | _None_
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://godoc.org/github.com/volatiletech/authboss/#Authboss.LoadClientStateMiddleware), [expire.Middleware](https://godoc.org/github.com/volatiletech/authboss/expire/#Middleware)
ClientStorage | Session
ServerStorer  | _None_
User          | [User](https://godoc.org/github.com/volatiletech/authboss/#User)
Values        | _None_
Mailer        | _None_

Expire simply uses sessions to track when the last action of a user is, if that action is longer
than configured then the session is deleted and the user removed from the request context.

This middleware should at a high level to ensure that "activity" is logged properly, as well as any
middlewares down the chain do not attempt to do anything with the user before it's removed from the
request context.

## Rendering Views

The authboss rendering system is simple. It's defined by one interface: [Renderer](https://godoc.org/github.com/volatiletech/authboss/#Renderer)

The renderer knows how to load templates, and how to render them with some data and that's it.
So let's examine the most common view types that you might want to use.

### HTML Views

When your app is a traditional web application and is generating it's HTML serverside using templates
this becomes a small wrapper on top of your rendering setup. For example if you're using `html/template`
then you could just use `template.New()` inside the `Load()` method and store that somewhere and
call `template.Execute()` in the `Render()` method.

There is also a very basic renderer: [Authboss Renderer](https://github.com/volatiletech/authboss-renderer) which has some very ugly built in views
and the ability to override them with your own if you don't want to integrate your own rendering
system into that interface.

### JSON Views

If you're building an API that's mostly backed by a javascript front-end, then you'll probably
want to use a renderer that returns JSON. There is a simple json renderer available in the [defaults package](https://github.com/volatiletech/authboss/defaults) package if you wish to use that.

### Data

The most important part about this interface is the data that you have to render.
There are several keys that are used throughout authboss that you'll want to render in your views.

They're in the file [html_data.go](https://github.com/volatiletech/authboss/blob/master/html_data.go)
and are constants prefixed with `Data`. See the documentation in that file for more information on
which keys exist and what they contain.

The default [responder](https://godoc.org/github.com/volatiletech/authboss/defaults/#Responder)
also happens to collect data from the Request context, and hence this is a great place to inject
data you'd like to render (for example data for your html layout, or csrf tokens).
