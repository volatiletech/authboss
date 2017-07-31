<img src="http://i.imgur.com/fPIgqLg.jpg"/>

Authboss
========

[![GoDoc](https://godoc.org/github.com/volatiletech/authboss?status.svg)](https://godoc.org/github.com/volatiletech/authboss)
[![Build Status](https://circleci.com/gh/volatiletech/authboss.svg?style=shield&circle-token=:circle-token)](https://circleci.com/gh/volatiletech/authboss)
[![Coverage Status](https://coveralls.io/repos/volatiletech/authboss/badge.svg?branch=master)](https://coveralls.io/r/volatiletech/authboss?branch=master)
[![Mail](https://img.shields.io/badge/mail%20list-authboss-lightgrey.svg)](https://groups.google.com/a/volatile.tech/forum/#!forum/authboss)

Authboss is a modular authentication system for the web. It tries to remove as much boilerplate and "hard things" as possible so that
each time you start a new web project in Go, you can plug it in, configure, and start building your app without having to build an
authentication system each time. This reduces the potential for mistakes since authentication is not exactly trivial and should hopefully
be generic enough to be plugged into all sorts of different web applications.

Note on Roadmap (v2)
========

It's been a long time since Authboss has been released, and there have been a lot of developments in Go as well as the community
and package management we'd like to take advantage of. There are several large refactorings that we think will make authboss
much cleaner and as a result easier to maintain as well (and maybe get some higher test coverage). So with that we're beginning
the v2 effort. Here's some of the things you can expect in terms of features and areas of concentration:

- JWT style auth for JS-based pages
- Cleaner separation of view from logic
- Storer rewrite
- Go 1.7 context usage

As far as the project goes this is how it will be managed:

- The current master HEAD will be available as v1.0.0
- No new features will be put in v1 branch, only critical bugfixes (life support only)
- v1 will be removed 6 months after the release of v2

Currently done:

- Main interfaces have been mostly completed
- Gopkg.in is abandoned as a versioning mechanism

Modules
========
Each module can be turned on simply by importing it and the side-effects take care of the rest. Not all the capabilities
of authboss are represented by a module, see [use cases](#use_cases) to view the supported use cases as well as how to
use them in your app.

Name           | Import Path                                                                                         | Description
---------------|-----------------------------------------------------------------------------------------------------|------------
Auth           | [github.com/volatiletech/authboss/auth](https://github.com/volatiletech/authboss/tree/master/auth)           | Provides database password authentication for users.
Confirm        | [github.com/volatiletech/authboss/confirm](https://github.com/volatiletech/authboss/tree/master/confirm)         | Sends an e-mail verification before allowing users to log in.
Lock           | [github.com/volatiletech/authboss/lock](https://github.com/volatiletech/authboss/tree/master/lock)               | Locks user accounts after N authentication failures in M time.
OAuth2         | [github.com/volatiletech/authboss/oauth2](https://github.com/volatiletech/authboss/tree/master/oauth2)           | Provides oauth2 authentication for users.
Recover        | [github.com/volatiletech/authboss/recover](https://github.com/volatiletech/authboss/tree/master/recover)         | Allows for password resets via e-mail.
Register       | [github.com/volatiletech/authboss/register](https://github.com/volatiletech/authboss/tree/master/register)       | User-initiated account creation.
Remember       | [github.com/volatiletech/authboss/remember](https://github.com/volatiletech/authboss/tree/master/remember)       | Persisting login sessions past session cookie expiry.

Getting Started
===============

Install the library and import it:

```
go get github.com/volatiletech/authboss
```

After that a good place to start in any Authboss implementation is the [configuration struct](http://godoc.org/github.com/volatiletech/authboss#Config).
There are many defaults setup for you but there are some elements that must be provided.
to find out what is configurable view the documentation linked to above, each struct element
is documented.

**Required options:**
- Storer or OAuth2Storer (for user storage)
- SessionStoreMaker (for flash messages, having a user logged in)
- CookieStoreMaker (for remember me cookies)
- XSRFName/XSRFMaker (for generating xsrf tokens to prevent xsrf attacks in authboss forms)

**Recommended options:**
- LogWriter: This is where authboss will log it's errors, as well as put status information on startup.
- MountPath: If you are mounting the authboss paths behind a certain path like /auth
- ViewsPath: Views to override the default authboss views go here (default: ./)
- Mailer: If you use any modules that make use of e-mails, this should be set.
- EmailFrom: The e-mail address you send your authboss notifications from.
- RootURL: This should be set if you use oauth2 or e-mails as it's required for generating URLs.
- ErrorHandler/NotFoundHandler/BadRequestHandler: You should display something that makes sense for your app with these.

The amount of code necessary to start and configure authboss is fairly minimal, of course this is excluding
your storer, cookie storer, session storer, xsrf maker implementations.

```go
ab := authboss.New() // Usually store this globally
ab.MountPath = "/authboss"
ab.LogWriter = os.Stdout

if err := ab.Init(); err != nil {
	// Handle error, don't let program continue to run
	log.Fatalln(err)
}

// Make sure to put authboss's router somewhere
http.Handle("/authboss", ab.NewRouter())
http.ListenAndServe(":8080", nil)
```

Once you've got this code set up, it's time to implement the use cases you care about.

<a name="use_cases"></a>Use Cases
=================================
- Get the logged in user ([goto](#current_user))
- Reset a User's password ([goto](#reset_password))
- User authentication via password ([goto](#auth))
- User authentication via OAuth2 ([goto](#oauth2))
- User registration ([goto](#register))
- Confirming registrations via e-mail ([goto](#confirm))
- Password recovery via e-mail ([goto](#recover))
- Persisting login sessions past session expiration ([goto](#remember))
- Locking user accounts after so many authentication failures ([goto](#lock))
- Expiring user sessions after inactivity ([goto](#expire))
- Form Field validation for Authboss forms ([goto](#validation))
- Redirect after authboss route (login/logout/oauth etc.) ([goto](#redirecting))

<a name="how_to"></a>How To
============================

There is a full implementation of authboss at: https://github.com/volatiletech/authboss-sample
This sample implements a blog with all of the modules with exception that it doesn't use the expiry middleware
since it conflicts with the remember module.

## <a name="current_user"></a>Get the logged in User

The current user should always be retrieved through the methods authboss.CurrentUser and authboss.CurrentUserP (panic version).
The reason for this is because they do checking against Remember me tokens and differentiate between normal and oauth2 logins.

The interface{} returned is actually your User struct (see: [Storers](#storers)) and you can convert it if it's not nil.

```go
func (a *Authboss) CurrentUser(w http.ResponseWriter, r *http.Request) (interface{}, error)
```

Return Values        | Meaning
---------------------|--------------------------------------------------------------
nil, nil             | The session had no user ID in it, no remember token, no user.
nil, ErrUserNotFound | Session had user ID, but user not found in database.
nil, err             | Some horrible error has occurred.
user struct, nil     | The user is logged in.

## <a name="reset_password"></a>Reset a User's password

Because on password reset various cleanings need to happen (for example Remember Me tokens
should all be deleted) setting the user's password yourself is not a good idea.

Authboss has the [UpdatePassword](http://godoc.org/github.com/volatiletech/authboss#Authboss.UpdatePassword) method for you to use. Please consult it's documentation
for a thorough explanation of each parameter and usage.

```go
func (a *Authboss) UpdatePassword(w http.ResponseWriter, r *http.Request, ptPassword string, user interface{}, updater func() error) error
```

An example usage might be:

```go
myUserSave := func() error {
	_, err := db.Exec(`update user set name = $1, password = $2 where id = $3`, user.Name, user.Password, user.ID)
	return err
}

// WARNING: Never pass the form value directly into the database as you see here :D
err := ab.UpdatePassword(w, r, r.FormValue("password"), &user1, myUserSave)
if err != nil {
	// Handle error here, in most cases this will be the error from myUserSave
}

```

## <a name="auth"></a>User Authentication via Password
**Requirements:**
- Auth module ([github.com/volatiletech/authboss/auth](https://github.com/volatiletech/authboss/tree/master/auth))
- [Storer](#storers)
- [Session Storer](#client_storers)
- [Views](#views)

**Storage Requirements:**
- Email OR Username (string)
- Password (string)

**How it works:** A route is registered for an authentication page. Link to the route, the user follows this link.
The Layout and the authboss login view is displayed. The user enters their credentials then the user credentials are verified. The storer will pull back the user and verify that the bcrypted password is correct, then log him in using
a session cookie and redirect him to the AuthLoginOKPath.

Another link is created for a logout. Simply link/redirect the user to this page and the user will be logged out.

## <a name="oauth2"></a> User Authentication via OAuth2
**Requirements:**
- OAuth2 module ([github.com/volatiletech/authboss/oauth2](https://github.com/volatiletech/authboss/tree/master/oauth2))
- [OAuth2Storer](#storers)
- OAuth2Providers
- [Session and Cookie Storers](#client_storers)

**Storage Requirements:**
- Oauth2Uid (string)
- Oauth2Provider (string)
- Oauth2Token (string)
- Oauth2Refresh (string)
- Oauth2Expiry (time.Time)

**How it works:** Routes are registered for each oauth2 provider you specify in the OAuth2Providers configuration.
You redirect the user to one of these initial routes (/mount_path/oauth2/providername) and the oauth2 module
will ensure the user logs in and receives a token. It then calls the Callback you specify in your OAuth2Provider
inside the config, this is responsible for returning various information, please see the docs for [OAuth2Provider](http://godoc.org/github.com/volatiletech/authboss#OAuth2Provider).
Once the callback is complete, the user is saved in the database, and logged in using the session.

Please note that in order to redirect to specific URLs or have the user use the remember module for oauth2 logins you must pass
query parameters in the initial route.

```go
params := url.Values{}
params.Set(authboss.CookieRemember, "true")
params.Set(authboss.FormValueRedirect, `/my/redirect/path`)
uri := `/authboss_mount_path/oauth2/google?` + params.Encode()

// Use uri to create a link for the user to log in with Google oauth2 in a template
// <a href="{{.googleOAuthUri}}">Log in with Google!</a>
```

**Examples:**
- [OAuth2Providers](https://github.com/volatiletech/authboss-sample/blob/master/blog.go#L57)
- [Writing a custom OAuth2Provider Callback](https://github.com/volatiletech/authboss/blob/master/oauth2/providers.go#L29)

## <a name="register"></a> User Registration
**Requirements:**
- Register module ([github.com/volatiletech/authboss/register](https://github.com/volatiletech/authboss/tree/master/register))
- [RegisterStorer](#storers)
- [Session Storer](#client_storers)
- [Views](#views)

**Storage Requirements:**
- Email OR Username (string)
- Password (string)

**How it works:** User is linked to registration page, the Layout and Registration view are rendered.
When the form is submitted, the policies are checked to ensure validation of all form fields (including any custom ones created
by overridden views). The password is bcrypt'd and the user is stored. If the confirm module has been loaded
the user will be redirected to the RegisterOKPath with a message telling them to check their e-mail and an e-mail will have been
sent. If the module is not loaded they will be automatically logged in after registration.

See also: [Validation](#validation)

## <a name="confirm"></a> Confirming Registrations
**Requirements:**
- Register module ([github.com/volatiletech/authboss/register](https://github.com/volatiletech/authboss/tree/master/register))
- Confirm module ([github.com/volatiletech/authboss/confirm](https://github.com/volatiletech/authboss/tree/master/confirm))
- [RegisterStorer](#storers)
- [Session and Cookie Storers](#client_storers)
- [Views](#views)

**Storage Requirements:**
- Email (string)
- ConfirmToken (string)
- Confirmed (bool)

**How it works:** After registration, the user will be informed they have an e-mail waiting for them. They click the link
provided in the e-mail and their account becomes confirmed, they will automatically be redirected to RegisterOKPath in the
default settings. If the AllowInsecureLoginAfterConfirm property is set to true, the user will also be automatically
logged in. The default for this property is set to false.


## <a name="recover"></a> Password Recovery
**Requirements:**
- Recover module ([github.com/volatiletech/authboss/recover](https://github.com/volatiletech/authboss/tree/master/recover))
- [RecoverStorer](#storers)
- [Session Storer](#client_storers)
- [Views](#views)

**Storage Requirements:**
- RecoverToken (string)
- RecoverTokenExpiry (time.Time)

**How it works:** The user goes to the password recovery page. They then enter their primary ID two times and press recover.
An e-mail is sent to the user that includes a token that expires after some time. The user clicks the link
in the e-mail and is prompted to enter a new password. Once the password they enter passes all policies
their new password is stored, they are redirected to the RecoverOkPath. If the AllowLoginAfterResetPassword property is set
to true, the user will also be automatically logged in. The default for this property is set to false.

## <a name="remember"></a> Remember Me (persistent login)
**Requirements:**
- Remember module ([github.com/volatiletech/authboss/remember](https://github.com/volatiletech/authboss/tree/master/remember))
- [RememberStorer](#storers)
- [Session and Cookie Storers](#client_storers)

**Storage Requirements:**

A separate table/Nested Array containing many tokens for any given user
- Token (string)

**RememberStorer:** A remember storer is an interface that must be satisfied by one of the authboss.Cfg.Storer or authboss.Cfg.OAuth2Storer if
neither satisfies the requirement the module will fail to load.

**How it works:** When the authentication form is submitted if the form value rm is set to "true" the remember module will automatically
create a remember token for the user and set this in the database as well as in a cookie. As for OAuth2 logins, it will look for
an encoded state parameter that is automatically included by simply passing rm=true in the query arguments to the initial oauth2 login
url ([see OAuth2](#oauth2) for more details).

If the user is not logged in and the CurrentUser method is called remember module will look for a token in the request and
attempt to use this to log the user in. If a valid token is found the user is logged in and receives a new token and the old one is deleted.

If a user recovers their password using the recover module, all remember me tokens are deleted for that user.

**Half Auth:** A session value with the name in the constant authboss.SessionHalfAuth will be set to "true" if the session was created
by a half-auth. Doing a full log in using the auth or oauth2 modules ensure this value is cleared. You should be careful about providing access
to pages with sensitive information if this value is true in the session, and force a full auth in these situations.

## <a name="lock"></a> Locking Accounts for Authentication Failures
**Requirements:**
- Lock module ([github.com/volatiletech/authboss/lock](https://github.com/volatiletech/authboss/tree/master/lock))
- [Storer](#storers)

**Storage Requirements:**
- AttemptNumber (int64)
- AttemptTime (time.Time)
- Locked (time.Time)

**How it works:** When a user fails authentication the attempt time is stored as well as the number of attempts being set to one.
If the user continues to fail authentication in the timeframe of AttemptTime + LockWindow
then the attempt number will continue to increase. Once the account number reaches the configured LockAfter amount the account will become
locked for the configured LockDuration. After this duration the user will be able to attempt to log in again.

## <a name="expire"></a> Expiring Inactive User Sessions
**Requirements:**
- [ExpireMiddleware](http://godoc.org/github.com/volatiletech/authboss#Authboss.ExpireMiddleware)
- [Session Storer](#client_storers)

**How it works:** A middleware is installed into the stack. This middleware uses the session to log the last action time of the user.
If the last action occurred longer than the configured expire time ago then the users login session will be deleted.

```go
mux := mux.NewRouter() // Gorilla Mux syntax
http.ListenAndServe(":8080", ab.ExpireMiddleware(mux)) // Install the middleware
```

## <a name="validation"></a> Validation

**Field validation:** Validation is achieved through the use of policies. These policies are in the configuration. They can be added for any field.
Any type can be used for validation that implements the Validator interface. Authboss supplies a quite flexible field validator called
[Rules](http://godoc.org/github.com/volatiletech/authboss#Rules) that you can use instead of writing your own. Validation errors are reported and
handled all in the same way, and the view decides how to display these to the user. See the examples or the authboss default view files to see
how to display errors.

```go
ab.Policies = []Validator{
	authboss.Rules{
		FieldName:       "username",
		Required:        true,
		MinLength:       2,
		MaxLength:       4,
		AllowWhitespace: false,
	},
}
```

**Confirmation fields:** To ensure one field matches a confirmation field, such as when registering and entering a password. Simply add
the field to the list of ConfirmFields, where each real entry in the array is two entries, the first being the name of the field to be confirmed
and the second being the name of the confirm field. These confirm fields are only used on the register page, and by default only has password but
you can add others.

```go
ab.ConfirmFields: []string{
	StorePassword, ConfirmPrefix + StorePassword,
},
```

## <a name="redirecting"></a> Redirecting after Authboss routes

Sometimes you want your web application to authenticate a user and redirect him back
to where he came from, or to a different page. You can do this by passing the "redir" query parameter
with a path to whatever URL you'd like. For example:

```html
<a href="/auth/login?redir=/userprofile">Login</a>
```

These redirection paths only occur on success paths currently, although this may change in the future.

## <a name="storers"></a> Implementing Storers
Authboss makes no presumptions about how you want to store your data. While different web frameworks have their own authentication plugins
such as passport or devise, Go has so no such standard framework and therefore we cannot make any of these assumptions and data handling
is a bit more manual.

There are three parts to storage: Storer interfaces, User Struct, Binding/Unbinding.

#### Storer Interfaces

- [Storer](http://godoc.org/github.com/volatiletech/authboss#Storer)
- [OAuth2Storer](http://godoc.org/github.com/volatiletech/authboss#OAuth2Storer)
- [ConfirmStorer](http://godoc.org/github.com/volatiletech/authboss/confirm#ConfirmStorer)
- [RecoverStorer](http://godoc.org/github.com/volatiletech/authboss/recover#RecoverStorer)
- [RegisterStorer](http://godoc.org/github.com/volatiletech/authboss/register#RegisterStorer)
- [RememberStorer](http://godoc.org/github.com/volatiletech/authboss/remember#RememberStorer)

Each of the store interfaces provides some amount of functionality to a module. Without the appropriate storer type the module cannot function.
Most of these interfaces simply do look ups on the user based on different field. Some of them like the RememberStorer are more special in their
functionality.

You can see an example here: [Blog Storer](https://github.com/volatiletech/authboss-sample/blob/master/storer.go).
This storer implements all 6 of the Storer Interfaces. If you don't use as many modules as the blog, you don't need to implement all of these methods.

Most of the methods return an (interface{}, error), the interface{} user struct that is described below. In cases where the queries produce no values (ie no user found),
special error values are returned, ErrUserNotFound and ErrTokenNotFound. Please consult the documentation for each Storer interface for more information
on what you should be returning in each situation.

#### User Struct

The idea is to create a struct that matches Authboss's storage requirements so that it can be easily serialized from and to using reflection available
through the methods: authboss.Attributes.Bind(), and authboss.Unbind(). These methods use a camel-case naming convention and do not have struct tags for
naming control (yet). Oauth2Uid in the struct -> "oauth2_uid" in the attributes map and vice versa. Bind() uses reflection to set attributes so the user
struct should be returned from storer methods as a pointer.

**Fields:** Each module in authboss has storage requirements. These are listed in the documentation but also at runtime authboss.ModuleAttributes is
available to list out each required field. The fields must be named appropriately and of the correct type.

**Choose a PrimaryID:** Email or Username can be selected for a primary id for the user (default email). This must be a unique field in the data store
and must be set to the Authboss configuration's PrimaryID, you can use authboss.StoreEmail and authboss.StoreUsername constants
to set it appropriately. Keep in mind that you can have both of these fields if you choose, but only one will be used
to log in with. Systems that wish to use Username should consider keeping e-mail address to allow the rest of the modules
that require email such as recover or confirm to function.

#### Binding/Unbinding

In your Create/Put/PutOAuth methods you will be handed an authboss.Attributes type. You can manually work with this type, and there are
many helper methods available but by far the easiest way is to simply pass in a correct user struct to it's .Bind() method. See examples below. In any type of Get
methods, the user struct should be filled with data, and passed back through the interface{} return parameter. authboss.Unbind() will be called on this struct to
extract it's data into authboss.Attributes, which is used for all authboss operations, and later Put will be called with the updated attributes for you to save them again.

#### Examples

- [Storer & OAuth2Storer combined](https://github.com/volatiletech/authboss-sample/blob/master/storer.go)

## <a name="client_storers"></a> Implementing Client Storers

[ClientStorer Interface](http://godoc.org/github.com/volatiletech/authboss#ClientStorer)

ClientStorer's encapsulate the functionality of cookies for the web application. The session storer is for session data, the cookie storer is actually
only used for the remember tokens so it should create cookies of very long durations (however long you want your users remembered for).

These are simple to implement and the following examples should show exactly what needs to be done. If you're using gorilla toolkit you can copy
these examples almost verbatim.

Keep in mind that these need not be only cookie-based, any storage medium that can reliably take a request/response pair and store session/client data
can be used. You could insert a redis backend here if you like that approach better than just cookies.

**Examples:**
- [Session Storer](https://github.com/volatiletech/authboss-sample/blob/master/session_storer.go)
- [Cookie Storer](https://github.com/volatiletech/authboss-sample/blob/master/cookie_storer.go)

## <a name="views"></a> Views
The view system in Authboss uses Go templates with the concepts of layout/views to render HTML to the user. It uses the authboss.HTMLData type
to pass data into templates. This HTMLData type has some helpers to merge different values in.

**ViewData:** There is a LayoutDataMaker function that should be defined in the config to provide any layout data (titles, additional data) for rendering authboss views.
This should typically include the keys: authboss.FlashSuccessKey, authboss.FlashErrorKey to display error and success messages from Authboss.

```go
// Example LayoutDataMaker
func layoutData(w http.ResponseWriter, r *http.Request) authboss.HTMLData {
	userInter, err := ab.CurrentUser(w, r)

	return authboss.HTMLData{
		"loggedin":               userInter != nil,
		authboss.FlashSuccessKey: ab.FlashSuccess(w, r),
		authboss.FlashErrorKey:   ab.FlashError(w, r),
	}
}
```

**Layouts:** There are 3 layouts to provide, these are specified in the configuration and you must load them yourself (using template.New().Parse() etc).
Each of these layouts should have a template defined within them like so: {{template "authboss" .}} if you are going to use this layout for other pages
that are not authboss-related, you can use an empty define at the end to prevent errors when the authboss template has not been provided: {{define "authboss"}}{{end}}
- Layout (for html/views)
- LayoutEmailHTML (for HTML e-mails)
- LayoutEmailText (for Text e-mails)

**Overriding Default Views:** The default authboss views are loaded automatically, they can be overridden simply by specifying the ViewPath (default ./) in the configuration
and placing files with the correct names in that directory.

Overiddable views are:

View                      | Name
--------------------------|--------------------------
Login Page                | login.html.tpl
Register Page             | register.html.tpl
Recover Page              | recover.html.tpl
Recover New Password      | recover_complete.html.tpl
Confirmation Email (html) | confirm_email.html.tpl
Confirmation Email (txt)  | confirm_email.txt.tpl
Recover Email (html)      | recover_email.html.tpl
Recover Email (txt)       | recover_email.txt.tpl

[Example Layout Configuration](https://github.com/volatiletech/authboss-sample/blob/master/blog.go#L47)

**Example Overriden Templates:**
- [Layout](https://github.com/volatiletech/authboss-sample/blob/master/views/layout.html.tpl)
- [Login](https://github.com/volatiletech/authboss-sample/blob/master/ab_views/login.html.tpl)
- [Recover](https://github.com/volatiletech/authboss-sample/blob/master/ab_views/recover.html.tpl)
- [Recover New Password](https://github.com/volatiletech/authboss-sample/blob/master/ab_views/recover_complete.html.tpl)
- [Register](https://github.com/volatiletech/authboss-sample/blob/master/ab_views/register.html.tpl)
