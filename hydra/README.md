# hydra
An hydra module to utilize [Authboss](https://github.com/volatiletech/authboss) as an 'identity' server for [hydra](https://github.com/ory/hydra). This is largely based on the reference implementation for the [login-consent-node](https://github.com/ory/hydra-login-consent-node). The module provides login, consent, and logout endpoints.

The following can be passed as environment variables:

| Name                          | Description                                                                                                                  | Default               |
|-------------------------------|------------------------------------------------------------------------------------------------------------------------------|-----------------------|
| `HYDRA_ADMIN_URL`             | e.g. http://hydra:4445                                                                                                       | http://localhost:4445 |
| `CONSENT_WHITELIST`           | Comma seperated list of urls that are automatically consented, this is intended for 1st party apps only. Set to `*` for all. |                       |
| `OVERRIDE_REQUESTED_AUDIENCE` | Set to true to parse requested audience from consent form and use that instead of audience from hydra.                       | `false`               |

TODO:

- [ ] add test coverage
- [ ] consider other module interaction and compatibility (2fa, remember,oauth)
- [ ] conform to module documentation
- [ ] add openid module that supports `GET` and `POST` for `/userinfo` as per spec
- [ ] add openid helpers and interfaces for documenting [standard](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) or reserved claims
