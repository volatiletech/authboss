# hConsenter

Minimalist go client for hydra login consent flow. Essentially it provides typed wrappers for the following paths. Response models are sourced from ory sdk. Hydra as an oath2 server needs an identity service, which can be created quickly with this client. 

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
