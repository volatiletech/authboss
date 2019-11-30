package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/volatiletech/authboss"
	// _ "github.com/volatiletech/authboss/auth"
	_ "github.com/ashtonian/authboss-hydra-consent/module"
	"github.com/volatiletech/authboss/confirm"
	"github.com/volatiletech/authboss/defaults"
	"github.com/volatiletech/authboss/lock"
	_ "github.com/volatiletech/authboss/recover"
	_ "github.com/volatiletech/authboss/register"
	"github.com/volatiletech/authboss/remember"

	abclientstate "github.com/volatiletech/authboss-clientstate"
	abrenderer "github.com/volatiletech/authboss-renderer"

	"github.com/aarondl/tpl"
	"github.com/go-chi/chi"
	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
	"github.com/justinas/nosurf"
)

var funcs = template.FuncMap{
	"formatDate": func(date time.Time) string {
		return date.Format("2006/01/02 03:04pm")
	},
	"yield": func() string { return "" },
}

var (
	flagDebug    = flag.Bool("debug", false, "output debugging information")
	flagDebugDB  = flag.Bool("debugdb", false, "output database on each request")
	flagDebugCTX = flag.Bool("debugctx", false, "output specific authboss related context keys on each request")
	flagAPI      = flag.Bool("api", false, "configure the app to be an api instead of an html app")
)

var (
	ab        = authboss.New()
	database  = NewMemStorer()
	schemaDec = schema.NewDecoder()

	sessionStore abclientstate.SessionStorer
	cookieStore  abclientstate.CookieStorer

	templates tpl.Templates
)

const (
	sessionCookieName = "ab_blog"
)

func setupAuthboss() {
	ab.Config.Paths.RootURL = "http://localhost:3000"

	// Set up our server, session and cookie storage mechanisms.
	// These are all from this package since the burden is on the
	// implementer for these.
	ab.Config.Storage.Server = database
	ab.Config.Storage.SessionState = sessionStore
	ab.Config.Storage.CookieState = cookieStore

	ab.Config.Core.ViewRenderer = abrenderer.NewHTML("/auth", "./")

	// We render mail with the authboss-renderer but we use a LogMailer
	// which simply sends the e-mail to stdout.
	ab.Config.Core.MailRenderer = abrenderer.NewEmail("/auth", "ab_views")

	// The preserve fields are things we don't want to
	// lose when we're doing user registration (prevents having
	// to type them again)
	ab.Config.Modules.RegisterPreserveFields = []string{"email", "name"}

	// TOTP2FAIssuer is the name of the issuer we use for totp 2fa
	ab.Config.Modules.TOTP2FAIssuer = "ABBlog"
	ab.Config.Modules.RoutesRedirectOnUnauthed = true

	// Turn on e-mail authentication required
	ab.Config.Modules.TwoFactorEmailAuthRequired = true

	// This instantiates and uses every default implementation
	// in the Config.Core area that exist in the defaults package.
	// Just a convenient helper if you don't want to do anything fancy.
	defaults.SetCore(&ab.Config, *flagAPI, false)

	// Here we initialize the bodyreader as something customized in or ord.
	//
	// We also change the validation for these fields
	// to be something less secure so that we can use test data easier.
	emailRule := defaults.Rules{
		FieldName: "email", Required: true,
		MatchError: "Must be a valid e-mail address",
		MustMatch:  regexp.MustCompile(`.*@.*\.[a-z]{1,}`),
	}
	passwordRule := defaults.Rules{
		FieldName: "password", Required: true,
		MinLength: 4,
	}
	nameRule := defaults.Rules{
		FieldName: "name", Required: true,
		MinLength: 2,
	}

	ab.Config.Core.BodyReader = defaults.HTTPBodyReader{
		ReadJSON: *flagAPI,
		Rulesets: map[string][]defaults.Rules{
			"register":    {emailRule, passwordRule, nameRule},
			"recover_end": {passwordRule},
		},
		Confirms: map[string][]string{
			"register":    {"password", authboss.ConfirmPrefix + "password"},
			"recover_end": {"password", authboss.ConfirmPrefix + "password"},
		},
		Whitelist: map[string][]string{
			"register": []string{"email", "name", "password"},
			"consent":  []string{"challenge"},
			"login":    []string{"challenge"},
			"logout":   []string{"challenge"},
		},
	}

	// Initialize authboss (instantiate modules etc.)
	if err := ab.Init(); err != nil {
		panic(err)
	}
}

func main() {
	flag.Parse()

	// Load our application's templates
	if !*flagAPI {
		// templates = tpl.Must(tpl.Load("views", "views/partials", "layout.html.tpl", funcs))
	}

	// Initialize Sessions and Cookies
	// Typically gorilla securecookie and sessions packages require
	// highly random secret keys that are not divulged to the public.
	//
	// In this example we use keys generated one time (if these keys ever become
	// compromised the gorilla libraries allow for key rotation, see gorilla docs)
	// The keys are 64-bytes as recommended for HMAC keys as per the gorilla docs.
	//
	// These values MUST be changed for any new project as these keys are already "compromised"
	// as they're in the public domain, if you do not change these your application will have a fairly
	// wide-opened security hole. You can generate your own with the code below, or using whatever method
	// you prefer:
	//
	//    func main() {
	//        fmt.Println(base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(64)))
	//    }
	//
	// We store them in base64 in the example to make it easy if we wanted to move them later to
	// a configuration environment var or file.
	cookieStoreKey, _ := base64.StdEncoding.DecodeString(`NpEPi8pEjKVjLGJ6kYCS+VTCzi6BUuDzU0wrwXyf5uDPArtlofn2AG6aTMiPmN3C909rsEWMNqJqhIVPGP3Exg==`)
	sessionStoreKey, _ := base64.StdEncoding.DecodeString(`AbfYwmmt8UCwUuhd9qvfNA9UCuN1cVcKJN1ofbiky6xCyyBj20whe40rJa3Su0WOWLWcPpO1taqJdsEI/65+JA==`)
	cookieStore = abclientstate.NewCookieStorer(cookieStoreKey, nil)
	cookieStore.HTTPOnly = false
	cookieStore.Secure = false
	sessionStore = abclientstate.NewSessionStorer(sessionCookieName, sessionStoreKey, nil)
	cstore := sessionStore.Store.(*sessions.CookieStore)
	cstore.Options.HttpOnly = false
	cstore.Options.Secure = false
	cstore.MaxAge(int((30 * 24 * time.Hour) / time.Second))

	// Initialize authboss
	setupAuthboss()

	// Set up our router
	schemaDec.IgnoreUnknownKeys(true)

	mux := chi.NewRouter()
	// The middlewares we're using:
	// - logger just does basic logging of requests and debug info
	// - nosurfing is a more verbose wrapper around csrf handling
	// - LoadClientStateMiddleware is required  for session/cookie stuff
	// - remember middleware logs users in if they have a remember token
	// - dataInjector is for putting data into the request context we need for our template layout
	mux.Use(logger, nosurfing, ab.LoadClientStateMiddleware, remember.Middleware(ab), dataInjector)

	// Authed routes
	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.Middleware2(ab, authboss.RequireNone, authboss.RespondUnauthorized), lock.Middleware(ab), confirm.Middleware(ab))
	})

	// Routes
	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.ModuleListMiddleware(ab))
		mux.Mount("/auth", http.StripPrefix("/auth", ab.Config.Core.Router))
	})

	if *flagAPI {
		// In order to have a "proper" API with csrf protection we allow
		// the options request to return the csrf token that's required to complete the request
		// when using post
		optionsHandler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-CSRF-TOKEN", nosurf.Token(r))
			w.WriteHeader(http.StatusOK)
		}

		// We have to add each of the authboss get/post routes specifically because
		// chi sees the 'Mount' above as overriding the '/*' pattern.
		routes := []string{"login", "logout", "recover", "recover/end", "register"}
		mux.MethodFunc("OPTIONS", "/*", optionsHandler)
		for _, r := range routes {
			mux.MethodFunc("OPTIONS", "/auth/"+r, optionsHandler)
		}
	}

	// Start the server
	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "3000"
	}
	log.Printf("Listening on localhost: %s", port)
	log.Println(http.ListenAndServe("localhost:"+port, mux))
}

func dataInjector(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := layoutData(w, &r)
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
		handler.ServeHTTP(w, r)
	})
}

// layoutData is passing pointers to pointers be able to edit the current po inter
// to the request. This is still safe as it still creates a new request and doesn't
// modify the old one, it just modifies what we're pointing to in our methods so
// we're able to skip returning an *http.Request everywhere
func layoutData(w http.ResponseWriter, r **http.Request) authboss.HTMLData {
	currentUserName := ""
	userInter, err := ab.LoadCurrentUser(r)

	fmt.Println(userInter, err)

	return authboss.HTMLData{
		"loggedin":          userInter != nil,
		"current_user_name": currentUserName,
		"csrf_token":        nosurf.Token(*r),
		"flash_success":     authboss.FlashSuccess(w, *r),
		"flash_error":       authboss.FlashError(w, *r),
	}
}

func index(w http.ResponseWriter, r *http.Request) {
}
