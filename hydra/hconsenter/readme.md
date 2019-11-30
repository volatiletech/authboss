# hConsenter

Minimalist go client for hydra login consent flow. Essentially it provides typed wrappers for the following paths. Response models are sourced from ory sdk. Hydra as an oath2 server requires a 'login consent flow', this client is intended to be all you'll need to interact with hydra to complete the flow.

```go
  PathGetLogin  = "/oauth2/auth/requests/login" // LoginRequest
  PathAcceptLogin  = "/oauth2/auth/requests/login/accept"  // RequestHandlerResponse
  PathRejectLogin  = "/oauth2/auth/requests/login/reject" // RequestHandlerResponse
  PathGetConsent  = "/oauth2/auth/requests/consent" // ConsentRequest
  PathAcceptConsent  = "/oauth2/auth/requests/consent/accept" // RequestHandlerResponse
  PathRejectConsent  = "/oauth2/auth/requests/consent/reject" // RequestHandlerResponse
  PathGetLogout  = "/oauth2/auth/requests/logout"   // LogoutRequest
  PathAcceptLogout  = "/oauth2/auth/requests/logout/accept" // RequestHandlerResponse
  PathRejectLogout  = "/oauth2/auth/requests/logout/reject" // RequestHandlerResponse
```
