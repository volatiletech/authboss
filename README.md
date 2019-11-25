# authboss-hydra-consent
An authboss-hydra-consent module to utilize [Authboss](https://github.com/volatiletech/authboss)  as an 'identity' server for hydra. This is largely based on [reference implementation](https://github.com/ory/hydra-login-consent-node). The module provides login, consent, and logout endpoints.

The following can be passed as environment variables:

| Name              | Description            | Default |
|-------------------|------------------------|---------|
| `HYDRA_ADMIN_URL` | e.g. http://hydra:4445 | _none_  |