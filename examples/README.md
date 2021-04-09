# Authorino examples

## Setup the environment

The simplest way to try the examples in this page is by launching a local test Kubernetes environment included in the Authorino examples.

Run from the root directory of the Authorino repo:

```sh
make local-setup
```

The above will setup the local environment, deploy Authorino, Envoy and the sample API to be protected called **Talker API**.

Some of the examples involve having an external identity provider (IdP), such as [Keycloak](https://www.keycloak.org) and/or [Dex](https://dexidp.io), to support authentication. To launch the local test environment including as well both these IdPs deployed to the cluster, run instead:

```sh
DEPLOY_IDPS=1 make local-setup
```

> **NOTE**: You can replace `DEPLOY_IDPS` above with `DEPLOY_KEYCLOAK` or `DEPLOY_DEX`, in case you only want one of these auth servers deployed.

Next, forward requests from your local host to the corresponding ports of Envoy, Keycloak, and Dex, running inside the cluster:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
kubectl -n authorino port-forward deployment/keycloak 8080:8080 & # (if using Keycloak)
kubectl -n authorino port-forward deployment/dex 5556:5556 &      # (if using Dex)
```

To cleanup, run:

```sh
make local-cluster-down
```

For more information on the deployment options and resources included in the local test Kubernetes environment included in Authorino examples, see [Deploying Authorino](/docs/deploy.md).

## Table of examples

- [Simple API key authentication](#simple-api-key-authentication)
- [Alternative credentials location](#alternative-credentials-location)
- [Forbidden IP](#forbidden-ip)
- [IP range allow list](#ip-range-allow-list)
- [Short-lived API keys (the non-OIDC “beta-testers” use case)](#short-lived-api-keys-the-non-oidc-beta-testers-use-case)
- [Read-only outside](#read-only-outside)
- [Kubernetes authentication](#kubernetes-authentication)
- [Simple OIDC (with Keycloak)](#simple-oidc-with-keycloak)
- [OIDC UserInfo](#oidc-userinfo)
- [Multiple OIDC providers (Keycloak and Dex)](#multiple-oidc-providers-keycloak-and-dex)
- [Resource-level authorization (with UMA resource registry)](#resource-level-authorization-with-uma-resource-registry)
- [Role-Based Access Control (RBAC) (with Keycloak realm roles)](#role-based-access-control-rbac-with-keycloak-realm-roles)

----
## Simple API key authentication

Simple authentication with API keys. Each API key is stored in a Kubernetes `Secret` resource that contains an `api_key` entry and labels matching the ones specified in the identity config.

Config:

```yaml
identity:
  - apiKey:
      labelSelectors: # the set must match labels added to secrets
        authorino.3scale.net/managed-by: authorino # required
        group: friends # user-defined (optional)
    […]
```

Secrets must contain:

```yaml
metadata:
  labels: # matching the the service `labelSelectors`
    authorino.3scale.net/managed-by: authorino
    group: friends
stringData:
  api_key: <random-generated-api-key>
```

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/simple-api-key.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/friend-1-api-key-1 created
```

### Try it out:

```sh
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://localhost:8000/hello # 200
curl -H 'Host: talker-api' -H 'Authorization: APIKEY nonono' http://localhost:8000/hello # 403
```

----
## Alternative credentials location

By default, Authorino expects credentials passed in the HTTP `Authorization` request header, with value following the default "Bearer" prefix. The example shows how to set up different locations for the credentials.

Config:

```yaml
identity:
  - credentials:
      in: authorization_header
      keySelector: Bearer
    […]
  - credentials:
      in: authorization_header
      keySelector: CustomPrefix # user-defined
    […]
  - credentials:
      in: custom_header
      keySelector: X-API-Key # user-defined
    […]
  - credentials:
      in: query
      keySelector: api_key # user-defined
    […]
  - credentials:
      in: cookie
      keySelector: API-KEY # user-defined
    […]
```

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/alternative-credentials-location.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/friend-1-api-key-1 created
```

### Try it out:

```sh
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://localhost:8000/hello # 200
curl -H 'Host: talker-api' 'http://localhost:8000/hello?api_key=ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' # 200
curl -H 'Host: talker-api' -H 'Authorization: Foo ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' 'http://localhost:8000/hello' # 403
```

----
## Forbidden IP

Uses Authorino's JSON pattern matching authorization for block requestes from a given client IP.

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/forbidden-ip.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/friend-1-api-key-1 created
```

### Try it out:

```sh
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://localhost:8000/hello # 200
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' -H 'X-Forwarded-For: 123.45.6.78' http://localhost:8000/hello # 403
```

----
## IP range allow list

Similar to the [Forbidden IP example](#forbidden-ip), to show how Authorino's JSON pattern matching authorization can be used to allow requests from a range of IPs only.

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/ip-range-allow-list.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/friend-1-api-key-1 created
```

### Try it out:

```sh
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' -H 'X-Forwarded-For: 192.168.1.10' http://localhost:8000/hello # 200
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://localhost:8000/hello # 403
```

----
## Short-lived API keys (the non-OIDC “beta-testers” use case)

Based on Authorino OPA implementation. The examples uses the `creationTimestamp` of the secrets (API keys) in a Rego policy to limit the time-span of API keys to 5 days only.


### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/short-lived-api-keys.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/friend-1-api-key-1 created
# secret/beta-tester-1-api-key-1 created
```

### Try it out:

```sh
# User of unlimited group "friends" (API key will never expire)
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://localhost:8000/hello # 200

# User of limited group "beta-testers" (API key expires after 5 days)
curl -H 'Host: talker-api' -H 'Authorization: APIKEY 76yh702XoA9GLzFHCuF42fq7lHJz5Etc' http://localhost:8000/hello # 200 (up to 5th day) / 403 (after 5th day)
```

----
## Read-only outside

It authorizes only GET requests whenever the source IP is not the one of a local secure network; full-access otherwise (inside the secure network).

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/read-only-outside.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/friend-1-api-key-1 created
```

### Try it out:

```sh
# safe origin
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' -H 'X-Forwarded-For: 192.168.1.10' http://localhost:8000/hello # 200
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' -H 'X-Forwarded-For: 192.168.1.10' -X POST http://localhost:8000/hello # 200

# unsafe origin
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' -H 'X-Forwarded-For: 123.45.6.78' http://localhost:8000/hello # 200
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' -H 'X-Forwarded-For: 123.45.6.78' -X POST http://localhost:8000/hello # 403
```

----
## Kubernetes authentication

It demonstrates Authorino authentication based on Kubernetes [TokenReview](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#tokenreview-v1-authentication-k8s-io) API.

Config:

```yaml
identity:
  - kubernetes:
      audiences: # user-defined; it must match the audiences inside the valid Kubernetes token; defaults to hostname of the requested service
        - talker-api
    […]
```

### Deploy the example:

```sh
sed -e "s/\${AUTHORINO_NAMESPACE}/authorino/g" ./examples/kubernetes-auth.yaml | kubectl -n authorino apply -f -
# service.config.authorino.3scale.net/talker-api-protection created
# serviceaccount/sa-token-issuer created
# clusterrolebinding.rbac.authorization.k8s.io/sa-token-issuer created
# serviceaccount/api-consumer created
```

### Try it out:

Get a valid Kubernetes token:

```sh
export KUBERNETES_API=$(kubectl cluster-info | head -n 1 | awk '{print $7}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
export TOKEN_ISSUER_TOKEN=$(kubectl -n authorino get secret/$(kubectl -n authorino get sa/sa-token-issuer -o json | jq -r '.secrets[0].name') -o json | jq -r '.data.token' | base64 -d)
export API_CONSUMER_TOKEN=$(curl -k -X "POST" "$KUBERNETES_API/api/v1/namespaces/authorino/serviceaccounts/api-consumer/token" \
     -H "Authorization: Bearer $TOKEN_ISSUER_TOKEN" \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d $'{ "apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": { "audiences": ["talker-api"], "expirationSeconds": 600 } }' | jq -r '.status.token')
```

Send requests to the API:

```sh
curl -H 'Host: talker-api' -H "Authorization: Bearer $API_CONSUMER_TOKEN" http://localhost:8000/hello # 200
```

----
## Simple OIDC (with Keycloak)

The example connects Authorino to a Keycloak realm as source of identities via OIDC. It also sets authorization to allow requests only from users with email verified.

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/simple-oidc.yaml
# service.config.authorino.3scale.net/talker-api-protection created
```

### Try it out:

Try it out with John

```sh
export ACCESS_TOKEN_JOHN=$(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://localhost:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/hello # 200
```

Try it out with Peter (email NOT verified)

```sh
export ACCESS_TOKEN_PETER=$(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=peter' -d 'password=p' "http://localhost:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_PETER" http://localhost:8000/hello # 403
```

----
## OIDC UserInfo

It leverages OIDC UserInfo requests during Authorino metadata phase to validate access tokens beyond timestamps and signature verification. Authorino sends a request to the OIDC issuer's UserInfo endpoint, thus live-checking for previous token revocation.

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/oidc-active-tokens-only.yaml
# service.config.authorino.3scale.net/talker-api-protection created
```

### Try it out:

> **NOTE:** Keycloak will not accept requests from tokens whose issuer domain name (the one in the "iss" claim) differs the domain name of the request to the Keycloak server. Since in the example Authorino is configured to reach the Keycloak server using the service host name inside the Kubernetes cluster (i.e. "keycloak"), one cannot issue a token outside the cluster (e.g. from the local host) with a different domain name (e.g. "localhost"). To work around this limitation, one may need to either get the token issued from a request within the cluster or by resolving outside the cluster the same domain name of the Keycloak server inside the cluster (i.e. "keycloak") to "127.0.0.1".

```sh
export $(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '"ACCESS_TOKEN="+.access_token,"REFRESH_TOKEN="+.refresh_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8000/hello # 200
```

Revoke access:

```sh
curl -H "Content-Type: application/x-www-form-urlencoded" -d "refresh_token=$REFRESH_TOKEN" -d 'token_type_hint=requesting_party_token' -u demo: "http://keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/logout"
```

Send another request:

```sh
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8000/hello # 403
```

----
## Multiple OIDC providers (Keycloak and Dex)

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/oidc-multiple-sources.yaml
# service.config.authorino.3scale.net/talker-api-protection created
```

### Try it out:

Keycloak user:

```sh
export ACCESS_TOKEN_JOHN=$(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/hello # 200
```

Dex user:

- On a web browser, open http://localhost:5556/auth?scope=openid%20profile%20email&response_type=code&client_id=demo&redirect_uri=http://localhost:3000/callback
- Login with username "marta@localhost" and password "password"
- Copy the authorization code in the URL of the page opened after the scope grant (the page will fail to load but you can still get the authorization code in the address bar)
- Paste the authorization code in the command below (placeholder `<authorization-code>`) to obtain the access token

```sh
export ACCESS_TOKEN_MARTA=$(curl -k -d 'grant_type=authorization_code' -d "code=<authorization-code>" -d 'client_id=demo' -d 'client_secret=aaf88e0e-d41d-4325-a068-57c4b0d61d8e' -d 'redirect_uri=http://localhost:3000/callback' "http://localhost:5556/token" | jq -r '.id_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_MARTA" http://localhost:8000/hello # 200
```

----
## Resource-level authorization (with UMA resource registry)

The example uses Keycloak User-Managed Access (UMA) implementation hosting resource data, that is later fetched by Authorino on every request, in metadata phase.

The Keycloak server also provides identities for OIDC authentication. The identity subject ("sub" claim) must match the owner of the requested resource, identitfied by the URI of the request.

According to the policy, everyone can send either GET or POST requests to `/greetings` and only the resource owners can send GET, PUT and DELETE requests to `/greetings/{resource-id}`.

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/resource-level-authz.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/talker-api-uma-credentials created
```

### Try it out:

Try out with John (owner of `/greetings/1`):

```sh
export ACCESS_TOKEN_JOHN=$(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://localhost:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/greetings # 200
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/greetings/1 # 200
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" -X DELETE http://localhost:8000/greetings/1 # 200
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/greetings/2 # 403
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/goodbye # 403
```

Try out with Jane (owner of `/greetings/2`):

```sh
export ACCESS_TOKEN_JANE=$(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' "http://localhost:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/greetings # 200
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/greetings/1 # 403
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" -X DELETE http://localhost:8000/greetings/1 # 403
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/greetings/2 # 200
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/goodbye # 403
```

Try out with Peter:

```sh
export ACCESS_TOKEN_PETER=$(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=peter' -d 'password=p' "http://localhost:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_PETER" http://localhost:8000/greetings # 200
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_PETER" http://localhost:8000/greetings/1 # 403
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_PETER" -X DELETE http://localhost:8000/greetings/1 # 403
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_PETER" http://localhost:8000/greetings/2 # 403
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_PETER" http://localhost:8000/goodbye # 403
```

----
## Role-Based Access Control (RBAC) (with Keycloak realm roles)

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/keycloak-rbac.yaml
# service.config.authorino.3scale.net/talker-api-protection created
```

### Try it out:

Try out with John (member user):

```sh
export ACCESS_TOKEN_JOHN=$(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://localhost:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/greetings # 200
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/goodbye # 403
```

Try out with Jane (admin user):

```sh
export ACCESS_TOKEN_JANE=$(curl -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' "http://localhost:8080/auth/realms/kuadrant/protocol/openid-connect/token" | jq -r '.access_token')

curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/greetings # 200
curl -H 'Host: talker-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/goodbye # 200
```
