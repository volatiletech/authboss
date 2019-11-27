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

# register auth-code-client
# Note that you need to add --token-endpoint-auth-method none if your clients are public (such as SPA apps and native apps) because the public clients cannot provide client secrets.
hydra clients create \
    --endpoint http://127.0.0.1:4445 \
    --id auth-code-client \
    --secret secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope openid,offline \
    --callbacks http://127.0.0.1:5555/callback

# run authboss
go run main.go

# start oath client flow
hydra token user \
    --client-id auth-code-client \
    --client-secret secret \
    --endpoint http://127.0.0.1:4444/ \
    --port 5555 \
    --scope openid,offline
```
