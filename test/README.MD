# Sample Flow

* install hydra cli

```sh
# spin up hydra, postgres, hydra-migrate, node consent flow
docker-compose -f docker-compose-ory-sample.yml up

# create oath client
hydra clients create \
    --endpoint http://127.0.0.1:4445/ \
    --id my-client \
    --secret secret \
    -g client_credentials

# grant client
hydra token client \
    --endpoint http://127.0.0.1:4444/ \
    --client-id my-client \
    --client-secret secret

hydra clients create \
    --endpoint http://127.0.0.1:4445 \
    --id auth-code-client \
    --secret secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope openid,offline \
    --callbacks http://127.0.0.1:5555/callback

```
