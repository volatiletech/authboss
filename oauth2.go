package authboss

import (
	"net/url"

	"golang.org/x/oauth2"
)

/*
OAuth2Provider is the entire configuration
required to authenticate with this provider.

The OAuth2Config does not need a redirect URL because it will
be automatically created by the route registration in the oauth2 module.

AdditionalParams can be used to specify extra parameters to tack on to the
end of the initial request, this allows for provider specific oauth options
like access_type=offline to be passed to the provider.

Callback gives the config and the token allowing an http client using the
authenticated token to be created. Because each OAuth2 implementation has a different
API this must be handled for each provider separately. It is used to return two things
specifically: UID (the ID according to the provider) and the Email address.
The UID must be passed back or there will be an error as it is the means of identifying the
user in the system, e-mail is optional but should be returned in systems using
emailing. The keys authboss.StoreOAuth2UID and authboss.StoreEmail can be used to set
these values in the authboss.Attributes map returned by the callback.

In addition to the required values mentioned above any additional
values that you wish to have in your user struct can be included here, such as the
Name of the user at the endpoint. Keep in mind that only types that are valid for the
Attributes type should be used: string, bool, time.Time, int64, or any type that implements
database/driver.Valuer.
*/
type OAuth2Provider struct {
	OAuth2Config     *oauth2.Config
	AdditionalParams url.Values
	Callback         func(oauth2.Config, *oauth2.Token) (Attributes, error)
}
