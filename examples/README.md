# Authorino examples

The examples provided in this page show several use cases and how to implement them as Authorino custom resources. Each example presents a feature of Authorino and is independent from the other.

For applications of Authorino into more complex combined real life-like guided examples, see Authorino [Tutorials](/docs/tutorials.md).

## Setting up the environment setup for the examples

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

> **NOTE:** You can replace `DEPLOY_IDPS` above with `DEPLOY_KEYCLOAK` or `DEPLOY_DEX`, in case you only want one of these auth servers deployed.

**For the examples using Keycloak** – Keycloak will reject tokens whose domain name of the issuer ("iss" claim) differs from the domain name of the request to the Keycloak server. In some examples, Authorino reaches the Keycloak server within the cluster, using the Kubernetes Keycloak service host name (i.e. "keycloak"). Therefore, you cannot get a token issued hitting Keycloak on `http://localhost:8080`, e.g., and later get this token validated through Authorino contacting Keycloak on `http://keycloak:8080`. To work around this limitation, you may need to either get tokens issued always from requests to Keycloak initiated inside the cluster, or, as assumed in the examples below, by resolving outside the cluster the same domain name assigned to the Keycloak service inside the cluster – i.e. `echo "127.0.0.1 keycloak" >> /etc/hosts`.

<br/>To finish the setup, forward requests from your local host to the corresponding ports of Envoy, Keycloak, and Dex, running inside the cluster:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
kubectl -n authorino port-forward deployment/keycloak 8080:8080 & # (if using Keycloak)
kubectl -n authorino port-forward deployment/dex 5556:5556 &      # (if using Dex)
```

<br/>To cleanup, run:

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
- [Simple OAuth2 (token introspection)](#simple-oauth2-token-introspection)
- [Simple OIDC (with Keycloak)](#simple-oidc-with-keycloak)
- [OIDC UserInfo](#oidc-userinfo)
- [Multiple OIDC providers (Keycloak and Dex)](#multiple-oidc-providers-keycloak-and-dex)
- [Resource-level authorization (with UMA resource registry)](#resource-level-authorization-with-uma-resource-registry)
- [Role-Based Access Control (RBAC) (with Keycloak realm roles)](#role-based-access-control-rbac-with-keycloak-realm-roles)
- [External HTTP metadata](#external-http-metadata)
- [Festival Wristbands](#festival-wristbands)

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
curl -H 'Host: talker-api' -H 'Authorization: APIKEY nonono' http://localhost:8000/hello # 401
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
CURRENT_K8S_CONTEXT=$(kubectl config view -o json | jq -r '."current-context"')
CURRENT_K8S_CLUSTER=$(kubectl config view -o json | jq -r --arg K8S_CONTEXT "${CURRENT_K8S_CONTEXT}"  '.contexts[] | select(.name == $K8S_CONTEXT) | .context.cluster')
export KUBERNETES_API=$(kubectl config view -o json | jq -r --arg K8S_CLUSTER "${CURRENT_K8S_CLUSTER}" '.clusters[] | select(.name == $K8S_CLUSTER) | .cluster.server')
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

## Simple OAuth2 (token introspection)

Introspection of supplied OAuth2 access tokens with Keycloak.

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/simple-oauth2.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/oauth2-token-introspection-credentials created
```

### Try it out:

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

The example sets two sources of identity to verify OIDC tokens (JWTs) – i.e., the Keycloak server and the Dex server, both running inside the cluster. If any of these providers accepts the token, Authorino succeeds in the identity verification phase.

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

Invalid token (neither Keycloak, nor Dex will accept it):

```sh
curl -H 'Host: talker-api' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' http://localhost:8000/hello # 403
```

----
## Resource-level authorization (with UMA resource registry)

The example uses Keycloak User-Managed Access (UMA) implementation hosting resource data, that is later fetched by Authorino on every request, in metadata phase. See [Authorino architecture > User-Managed Access (UMA)](/docs/architecture.md#user-managed-access-uma) for more information.

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

----
## External HTTP metadata

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/ext-http-metadata.yaml
# service.config.authorino.3scale.net/talker-api-protection configured
# secret/echo-metadata-shared-auth configured
# secret/friend-1-api-key-1 configured
```
### Try it out:

```sh
# safe origin
curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://localhost:8000/hello # 200
```

----
## Festival Wristbands

Festival Wristbands are OpenID Connect JSON Web Tokens (JWTs) issued by Authorino at the end of the auth pipeline and passed back to the client in the HTTP response header `X-Ext-Auth-Wristband`. It is an opt-in feature that can be used to enable Edge Authentication and token normalization. Authorino wristbands can also be used as vessels to carry from the external authorization back to the client (with custom claims).

In this example, we set an API protection that issues a wristband after a successful authentication via API key. The wristband contains standard JWT claims such as `iss`, `iat`, and `exp`. It also contains with 2 custom claims: a static value `aud=internal` and a dynamic value `born` that fetches from the authorization JSON the creation timestamp of the secret that represents the API key used to authenticate. The tokens expires after 300 seconds and is signed using an elliptic curve private key stored in a Kubernetes secret.

The example also sets the API protection to accepts the same wristbands as valid authentication tokens to consume the API. This is also option and rely on Authorino's OIDC identity verification feature.

### Deploy the example:

```sh
kubectl -n authorino apply -f ./examples/wristband.yaml
# service.config.authorino.3scale.net/talker-api-protection created
# secret/edge-api-key-1 created
# secret/my-signing-key created
# secret/my-old-signing-key created
```

### Try it out:

Obtain a wristband by successfully authenticating via API key:

```sh
export WRISTBAND=$(curl -H 'Host: talker-api' -H 'Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx' http://localhost:8000/hello | jq -r '.headers.HTTP_X_EXT_AUTH_WRISTBAND')
```

Send requests to the same API now authenticating with the wristband:

```sh
curl -H 'Host: talker-api' -H "Authorization: Bearer $WRISTBAND" http://localhost:8000/hello -v # 200
```

The payload of the wristband (decoded) shall look like the following:

```jsonc
{
  "aud": "internal", # custom claim (static value)
  "born": "2021-05-13T15:42:41Z", # custom claim (dynamic value)
  "exp": 1620921395,
  "iat": 1620921095,
  "iss": "http://authorino-authorization:8003/authorino/talker-api-protection",
  "sub": "84d3f3a06f5569e06a050516363f0a65c1789d3433bb4fed5d48801997d5c30e" # SHA256 of the resolved identity in the initial request (based on API key auth)
}
```

To discover the OpenID Connect configuration and JSON Web Key Set (JWKS) to verify and validate wristbands issued on requests to this protected API:

```
kubectl -n authorino port-forward service/authorino-authorization 8003:8003
```

OpenID Connect configuration well-known endpoint:<br/>
http://localhost:8003/authorino/talker-api-protection/.well-known/openid-configuration

JSON Web Key Set (JWKS) well-known endpoint:<br/>
http://localhost:8003/authorino/talker-api-protection/.well-known/openid-connect/certs
