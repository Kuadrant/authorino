# Logging

## Log levels and log modes

Authorino outputs 3 levels of log messages: (from lowest to highest level)
1. `debug`
2. `info` (default)
3. `error`

`info` logging is restricted to high-level information of the gRPC and HTTP authorization services, limiting messages to incomming request and respective outgoing response logs, with reduced details about the corresponding objects (request payload and authorization result), and without any further detailed logs of the steps in between, except for errors.

Only `debug` logging will include processing details of each [Auth Pipeline](architecture.md#the-auth-pipeline), such as intermediary requests to validate identities with external auth servers, requests to external sources of auth metadata or authorization policies.

To configure the desired log level, set the environment variable `LOG_LEVEL` to one of the supported values listed above. Default log level is `info`.

Apart from log level, Authorino can output messages to the logs in 2 different formats:
- `production` (default): each line is a parseable JSON object with properties `{"level":string, "ts":int, "msg":string, "logger":string, extra values...}`
- `development`: more human-readable outputs, extra stack traces and logging info, plus extra values output as JSON, in the format: `<timestamp-iso-8601>\t<log-level>\t<logger>\t<message>\t{extra-values-as-json}`

To configure the desired log mode, set the environment variable `LOG_MODE` to one of the supported values listed above. Default log level is `production`.

## Sensitive data output to the logs

Authorino will never output HTTP headers and query string parameters to `info` log messages, as such values usually include sensitive data (e.g. access tokens, API keys and Authorino [Festival Wristbands](architecture.md#festival-wristband-authentication)). However, `debug` log messages may include such sensitive information and those are not redacted.

Therefore, **DO NOT USE `debug` LOG LEVEL IN PRODUCTION**! Instead use either `info` or `error`.

## Tracing ID

Most log messages associated with an auth request include a `request id` extra value. The value represents the ID of the external authorization request received and processed by Authorino. This value is particularly useful to link incomming request and outgoing response log messages, as well as the more fine-grained log details available only in `debug` level.

## Typical log messages

Some typical log messages output by the Authorino service are listed in the table below:

| logger | level | message | extra values |
| -------|-------|---------|--------|
| n/a | `info` | "setting instance base logger" | `min level=info\|debug`, `mode=production\|development` |
| n/a | `info` | "attempting to acquire leader lease authorino/cb88a58a.authorino.3scale.net...\n" | |
| n/a | `info` | "successfully acquired lease authorino/cb88a58a.authorino.3scale.net\n" | |
| `main` | `info` | "starting grpc service" | `port`, `tls` |
| `main` | `error` | "failed to obtain port for grpc auth service" | |
| `main` | `error` | "failed to load tls cert" | |
| `main` | `error` | "failed to start grpc service" | |
| `main` | `info` | "starting oidc service" | `port`, `tls` |
| `main` | `error` | "failed to obtain port for http oidc service" | |
| `main` | `error` | "failed to start oidc service" | |
| `main` | `info` | "starting manager" | |
| `main` | `error` | "unable to start manager" | |
| `main` | `error` | "unable to create controller" | `controller=authconfig\|secret\|authconfigstatusupdate` |
| `main` | `error` | "problem running manager" | |
| `main` | `info` | "starting status update manager" | |
| `main` | `error` | "unable to start status update manager" | |
| `main` | `error` | "problem running status update manager" | |
| `controller-runtime.metrics` | `info` | "metrics server is starting to listen" | `addr` |
| `controller-runtime.manager` | `info` | "starting metrics server" | `path`
| `controller-runtime.manager.events` | `debug` | "Normal" | `object={kind=ConfigMap, apiVersion=v1}`, `reason=LeaderElection`, `message="authorino-controller-manager-* became leader"`
| `controller-runtime.manager.events` | `debug` | "Normal" | `object={kind=Lease, apiVersion=coordination.k8s.io/v1}`, `reason=LeaderElection`, `message="authorino-controller-manager-* became leader"`
| `controller-runtime.manager.controller.authconfig` | `info` | "resource reconciled" | |
| `controller-runtime.manager.controller.authconfig` | `info` | "object has been deleted, deleted related configs" | |
| `controller-runtime.manager.controller.authconfig` | `info` | "host already taken in another namespace" | |
| `controller-runtime.manager.controller.authconfig.statusupdater` | `info` | "resource status updated" | |
| `controller-runtime.manager.controller.secret` | `info` | "resource reconciled" | |
| `controller-runtime.manager.controller.secret` | `info` | "could not reconcile authconfigs using api key authentication" | |
| `service.oidc` | `info` | "request received" | `realm`, `config`, `path` |
| `service.oidc` | `error` | "failed to serve oidc request" | |
| `service.auth` | `info` | "incoming authorization request" | `request id`, `object` |
| `service.auth` | `debug` | "incoming authorization request" | `request id`, `object` |
| `service.auth` | `info` | "outgoing authorization response" | `request id`, `authorized`, `response`, `object` |
| `service.auth` | `debug` | "outgoing authorization response" | `request id`, `authorized`, `response`, `object` |
| `service.auth` | `error` | "failed to create dynamic metadata" | `request id`, `object` |
| `service.authpipeline` | `debug` | "skipping config" | `request id`, `config`, `reason` |
| `service.authpipeline.identity` | `debug` | "identity validated" | `request id`, `config`, `object` |
| `service.authpipeline.identity` | `debug` | "cannot validate identity" | `request id`, `config`, `reason` |
| `service.authpipeline.identity` | `error` | "failed to extend identity object" | `request id`, `config`, `object` |
| `service.authpipeline.metadata` | `debug` | "fetched auth metadata" | `request id`, `config`, `object` |
| `service.authpipeline.metadata` | `debug` | "cannot fetch metadata" | `request id`, `config`, `reason` |
| `service.authpipeline.authorization` | `debug` | "evaluating for input" | `request id`, `input` |
| `service.authpipeline.authorization` | `debug` | "access granted" | `request id`, `config`, `object` |
| `service.authpipeline.authorization` | `debug` | "access denied" | `request id`, `config`, `reason` |
| `service.authpipeline.response` | `debug` | "dynamic response built" | `request id`, `config`, `object` |
| `service.authpipeline.response` | `debug` | "cannot build dynamic response" | `request id`, `config`, `reason` |
| `authcredential` | `error` | "the credential was not found in the request header" | |
| `authcredential` | `error` | "the Authorization header is not set" | |
| `authcredential` | `error` | "the Cookie header is not set" | |
| `identity.oauth2` | `debug` | "sending token introspection request" | `request id`, `url`, `data` |
| `identity.apikey` | `error` | "Something went wrong fetching the authorized credentials" | |
| `identity.oidc` | `error` | "failed to discovery openid connect configuration" | `endpoint` |
| `identity.kubernetesauth` | `debug` | "calling kubernetes token review api" | `request id`, `tokenreview` |
| `metadata.http` | `debug` | "sending request" | `request id`, `method`, `url`, `headers` |
| `metadata.userinfo` | `debug` | "fetching user info" | `request id`, `endpoint` |
| `metadata.uma` | `debug` | "requesting pat" | `request id`, `url`, `data`, `headers` |
| `metadata.uma` | `debug` | "querying resources by uri" | `request id`, `url` |
| `metadata.uma` | `debug` | "getting resource data" | `request id`, `url` |
| `authorization.opa` | `error` | "Invalid response from OPA policy evaluation" | `secret` |
| `authorization.opa` | `error` | "Failed to precompile OPA policy" | `secret` |
| `authorization.kubernetesauthz` | `debug` | "calling kubernetes subject access review api" | `request id`, `subjectaccessreview` |

### Examples

The examples below are all with `LOG_LEVEL=debug` and `LOG_MODE=production`.

#### Booting up the service:

```jsonc
{"level":"info","ts":1634550867.2342405,"msg":"setting instance base logger","min level":"debug","mode":"production"}
{"level":"info","ts":1634550868.2441845,"logger":"controller-runtime.metrics","msg":"metrics server is starting to listen","addr":"127.0.0.1:8080"}
{"level":"info","ts":1634550868.2448874,"logger":"main","msg":"starting grpc service","port":"50051","tls":true}
{"level":"info","ts":1634550868.2457223,"logger":"main","msg":"starting oidc service","port":"8083","tls":true}
{"level":"info","ts":1634550868.24923,"logger":"main","msg":"starting manager"}
{"level":"info","ts":1634550868.251503,"logger":"controller-runtime.manager","msg":"starting metrics server","path":"/metrics"}
{"level":"info","ts":1634550868.33324,"logger":"controller-runtime.manager.controller.authconfig","msg":"Starting EventSource","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig","source":"kind source: /, Kind="}
{"level":"info","ts":1634550868.3337233,"logger":"controller-runtime.manager.controller.authconfig","msg":"Starting Controller","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig"}
{"level":"info","ts":1634550868.3333747,"logger":"controller-runtime.manager.controller.secret","msg":"Starting EventSource","reconciler group":"","reconciler kind":"Secret","source":"kind source: /, Kind="}
{"level":"info","ts":1634550868.334799,"logger":"controller-runtime.manager.controller.secret","msg":"Starting Controller","reconciler group":"","reconciler kind":"Secret"}
{"level":"info","ts":1634550869.0391212,"logger":"controller-runtime.manager.controller.secret","msg":"Starting workers","reconciler group":"","reconciler kind":"Secret","worker count":1}
{"level":"info","ts":1634550869.0392976,"logger":"controller-runtime.manager.controller.authconfig","msg":"Starting workers","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig","worker count":1}
{"level":"info","ts":1634550869.2370462,"logger":"main","msg":"starting status update manager"}
{"level":"info","ts":1634550869.2373037,"msg":"attempting to acquire leader lease authorino/cb88a58a.authorino.3scale.net...\n"}
{"level":"info","ts":1634550884.4037402,"msg":"successfully acquired lease authorino/cb88a58a.authorino.3scale.net\n"}
{"level":"debug","ts":1634550884.4042945,"logger":"controller-runtime.manager.events","msg":"Normal","object":{"kind":"ConfigMap","namespace":"authorino","name":"cb88a58a.authorino.3scale.net","uid":"5764d2b1-1310-4b24-ac28-32320d7fb074","apiVersion":"v1","resourceVersion":"81123"},"reason":"LeaderElection","message":"authorino-controller-manager-76846d6978-hkg7t_be2e4ef2-4b8d-409f-83d9-c133053d2ad3 became leader"}
{"level":"debug","ts":1634550884.4046965,"logger":"controller-runtime.manager.events","msg":"Normal","object":{"kind":"Lease","namespace":"authorino","name":"cb88a58a.authorino.3scale.net","uid":"69da183c-5d2e-4f34-a8e1-847726c5a16c","apiVersion":"coordination.k8s.io/v1","resourceVersion":"81124"},"reason":"LeaderElection","message":"authorino-controller-manager-76846d6978-hkg7t_be2e4ef2-4b8d-409f-83d9-c133053d2ad3 became leader"}
{"level":"info","ts":1634550884.4058003,"logger":"controller-runtime.manager.controller.authconfig","msg":"Starting EventSource","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig","source":"kind source: /, Kind="}
{"level":"info","ts":1634550884.4062388,"logger":"controller-runtime.manager.controller.authconfig","msg":"Starting Controller","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig"}
{"level":"info","ts":1634550884.5083082,"logger":"controller-runtime.manager.controller.authconfig","msg":"Starting workers","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig","worker count":1}
```

#### Reconciling an `AuthConfig` and related 2 API key `Secret`s:

```jsonc
{"level":"info","ts":1634551277.5473623,"logger":"controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"authorino/talker-api-protection"}
{"level":"info","ts":1634551276.7289426,"logger":"controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status updated","authconfig/status":"authorino/talker-api-protection"}
{"level":"info","ts":1634551276.9598267,"logger":"controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"authorino/api-key-1"}
{"level":"info","ts":1634551277.649606,"logger":"controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"authorino/talker-api-protection"}
{"level":"info","ts":1634551277.0289664,"logger":"controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"authorino/api-key-2"}
{"level":"info","ts":1634551277.7521014,"logger":"controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"authorino/talker-api-protection"}
{"level":"info","ts":1634551277.5533233,"logger":"controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"authorino/talker-api-protection"}
{"level":"info","ts":1634551276.7885637,"logger":"controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status updated","authconfig/status":"authorino/talker-api-protection"}
```

#### Enforcing `AuthConfig` while authenticating with Kubernetes authentication token:

<details>
  <summary>`AuhConfig` composed of:</summary>

  - identity: k8s-auth, oidc, oauth2, apikey
  - metadata: http, oidc userinfo
  - authorization: opa, k8s-authz
  - response: wristband
</details>

```jsonc
{"level":"info","ts":1634551413.9954116,"logger":"service.auth","msg":"incoming authorization request","request id":"4319406766266888331","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":37552}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"http":{"id":"4319406766266888331","method":"GET","path":"/hello","host":"talker-api","scheme":"http"}}}}
{"level":"debug","ts":1634551413.995606,"logger":"service.auth","msg":"incoming authorization request","request id":"4319406766266888331","object":"source:{address:{socket_address:{address:\"127.0.0.1\"  port_value:37552}}}  destination:{address:{socket_address:{address:\"127.0.0.1\"  port_value:8000}}}  request:{time:{seconds:1634551413  nanos:977636000}  http:{id:\"4319406766266888331\"  method:\"GET\"  headers:{key:\":authority\"  value:\"talker-api\"}  headers:{key:\":method\"  value:\"GET\"}  headers:{key:\":path\"  value:\"/hello\"}  headers:{key:\":scheme\"  value:\"http\"}  headers:{key:\"accept\"  value:\"*/*\"}  headers:{key:\"authorization\"  value:\"Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IlQtcHlkNkhxZy1IclQyQWU2R0JldXVUNjB3T3ltWEpobmdXQ1M2aUNUVlkifQ.eyJhdWQiOlsidGFsa2VyLWFwaSJdLCJleHAiOjE2MzQ1NTIwMDUsImlhdCI6MTYzNDU1MTQwNSwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXItMSIsInVpZCI6IjIzMzViMmUyLTc5YjAtNGI1OC05ZGUyLWI1OWI5NmI3ZjM2MyJ9fSwibmJmIjoxNjM0NTUxNDA1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YXV0aG9yaW5vOmFwaS1jb25zdW1lci0xIn0.cggcG0ylvXqK9Ifm2Svch8KY1rlwxqitSZ_lyujNpx_uL6NP8K4QPviOMhu9qssR8LkX11yy1oR5wlGr-1iDB-pMZ_zm7LCnzj6xoUJF79p0uV06ijTLiEOSvIge9SGDA-ERdqLqn0-SH83--Nl7kyi9mkJihGBSw3TxEZyLqP7hsWL1OpoNolR6DrUzqCswXWGBtVJnNPeLTK0SIcw1hBKL_L3DsVNKNbBtsWjZapBUCv_UD0bf49tHsqt_XPZF2p7ZIqpSvzkBN8sfWTtwdms-y9jww3WWSbOdD4eVNh4_glWcSnjfgyRTyV0rBFGsPppxWNpLvUEqnxoicXiTsg\"}  headers:{key:\"user-agent\"  value:\"curl/7.65.3\"}  headers:{key:\"x-envoy-internal\"  value:\"true\"}  headers:{key:\"x-forwarded-for\"  value:\"10.244.0.10\"}  headers:{key:\"x-forwarded-proto\"  value:\"http\"}  headers:{key:\"x-request-id\"  value:\"d84abac9-f245-4704-942d-242ae8f0a97e\"}  path:\"/hello\"  host:\"talker-api\"  scheme:\"http\"  protocol:\"HTTP/1.1\"}}  context_extensions:{key:\"virtual_host\"  value:\"local_service\"}  metadata_context:{}"}
{"level":"debug","ts":1634551414.0080953,"logger":"identity.kubernetesauth","msg":"calling kubernetes token review api","request id":"4319406766266888331","tokenreview":{"metadata":{"creationTimestamp":null},"spec":{"token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IlQtcHlkNkhxZy1IclQyQWU2R0JldXVUNjB3T3ltWEpobmdXQ1M2aUNUVlkifQ.eyJhdWQiOlsidGFsa2VyLWFwaSJdLCJleHAiOjE2MzQ1NTIwMDUsImlhdCI6MTYzNDU1MTQwNSwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXItMSIsInVpZCI6IjIzMzViMmUyLTc5YjAtNGI1OC05ZGUyLWI1OWI5NmI3ZjM2MyJ9fSwibmJmIjoxNjM0NTUxNDA1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YXV0aG9yaW5vOmFwaS1jb25zdW1lci0xIn0.cggcG0ylvXqK9Ifm2Svch8KY1rlwxqitSZ_lyujNpx_uL6NP8K4QPviOMhu9qssR8LkX11yy1oR5wlGr-1iDB-pMZ_zm7LCnzj6xoUJF79p0uV06ijTLiEOSvIge9SGDA-ERdqLqn0-SH83--Nl7kyi9mkJihGBSw3TxEZyLqP7hsWL1OpoNolR6DrUzqCswXWGBtVJnNPeLTK0SIcw1hBKL_L3DsVNKNbBtsWjZapBUCv_UD0bf49tHsqt_XPZF2p7ZIqpSvzkBN8sfWTtwdms-y9jww3WWSbOdD4eVNh4_glWcSnjfgyRTyV0rBFGsPppxWNpLvUEqnxoicXiTsg","audiences":["talker-api"]},"status":{"user":{}}}}
{"level":"debug","ts":1634551414.0192087,"logger":"service.authpipeline.identity","msg":"cannot validate identity","request id":"4319406766266888331","config":{"Name":"api-keys","ExtendedProperties":[{"Name":"sub","Value":{"Static":null,"Pattern":"auth.identity.metadata.annotations.userid"}}],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":{"AuthCredentials":{"KeySelector":"APIKEY","In":"authorization_header"},"Name":"api-keys","LabelSelectors":{"audience":"talker-api","authorino.3scale.net/managed-by":"authorino"}},"KubernetesAuth":null},"reason":"credential not found"}
{"level":"debug","ts":1634551414.0302806,"logger":"identity.oauth2","msg":"sending token introspection request","request id":"4319406766266888331","url":"http://talker-api:523b92b6-625d-4e1e-a313-77e7a8ae4e88@keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token/introspect","data":"token=eyJhbGciOiJSUzI1NiIsImtpZCI6IlQtcHlkNkhxZy1IclQyQWU2R0JldXVUNjB3T3ltWEpobmdXQ1M2aUNUVlkifQ.eyJhdWQiOlsidGFsa2VyLWFwaSJdLCJleHAiOjE2MzQ1NTIwMDUsImlhdCI6MTYzNDU1MTQwNSwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXItMSIsInVpZCI6IjIzMzViMmUyLTc5YjAtNGI1OC05ZGUyLWI1OWI5NmI3ZjM2MyJ9fSwibmJmIjoxNjM0NTUxNDA1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YXV0aG9yaW5vOmFwaS1jb25zdW1lci0xIn0.cggcG0ylvXqK9Ifm2Svch8KY1rlwxqitSZ_lyujNpx_uL6NP8K4QPviOMhu9qssR8LkX11yy1oR5wlGr-1iDB-pMZ_zm7LCnzj6xoUJF79p0uV06ijTLiEOSvIge9SGDA-ERdqLqn0-SH83--Nl7kyi9mkJihGBSw3TxEZyLqP7hsWL1OpoNolR6DrUzqCswXWGBtVJnNPeLTK0SIcw1hBKL_L3DsVNKNbBtsWjZapBUCv_UD0bf49tHsqt_XPZF2p7ZIqpSvzkBN8sfWTtwdms-y9jww3WWSbOdD4eVNh4_glWcSnjfgyRTyV0rBFGsPppxWNpLvUEqnxoicXiTsg&token_type_hint=requesting_party_token"}
{"level":"debug","ts":1634551414.1077797,"logger":"service.authpipeline.identity","msg":"cannot validate identity","request id":"4319406766266888331","config":{"Name":"keycloak-jwts","ExtendedProperties":[],"OAuth2":null,"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"},"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":null},"reason":"failed to verify signature: failed to verify id token signature"}
{"level":"debug","ts":1634551414.109044,"logger":"service.authpipeline.identity","msg":"identity validated","request id":"4319406766266888331","config":{"Name":"k8s-service-accounts","ExtendedProperties":[],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"object":{"aud":["talker-api"],"exp":1634552005,"iat":1634551405,"iss":"https://kubernetes.default.svc.cluster.local","kubernetes.io":{"namespace":"authorino","serviceaccount":{"name":"api-consumer-1","uid":"2335b2e2-79b0-4b58-9de2-b59b96b7f363"}},"nbf":1634551405,"sub":"system:serviceaccount:authorino:api-consumer-1"}}
{"level":"debug","ts":1634551414.1092317,"logger":"metadata.uma","msg":"requesting pat","request id":"4319406766266888331","url":"http://talker-api:523b92b6-625d-4e1e-a313-77e7a8ae4e88@keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token","data":"grant_type=client_credentials","headers":{"Content-Type":["application/x-www-form-urlencoded"]}}
{"level":"debug","ts":1634551414.1120772,"logger":"metadata.http","msg":"sending request","request id":"4319406766266888331","method":"GET","url":"http://talker-api.authorino.svc.cluster.local:3000/metadata?encoding=text/plain&original_path=/hello","headers":{"Content-Type":["text/plain"]}}
{"level":"debug","ts":1634551414.121508,"logger":"service.authpipeline.metadata","msg":"cannot fetch metadata","request id":"4319406766266888331","config":{"Name":"oidc-userinfo","UserInfo":{"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"}},"UMA":null,"GenericHTTP":null},"reason":"Missing identity for OIDC issuer http://keycloak:8080/auth/realms/kuadrant. Skipping related UserInfo metadata."}
{"level":"debug","ts":1634551414.2071698,"logger":"metadata.uma","msg":"querying resources by uri","request id":"4319406766266888331","url":"http://keycloak:8080/auth/realms/kuadrant/authz/protection/resource_set?uri=/hello"}
{"level":"debug","ts":1634551414.2223427,"logger":"service.authpipeline.metadata","msg":"fetched auth metadata","request id":"4319406766266888331","config":{"Name":"http-metadata","UserInfo":null,"UMA":null,"GenericHTTP":{"Endpoint":"http://talker-api.authorino.svc.cluster.local:3000/metadata?encoding=text/plain&original_path={context.request.http.path}","Method":"GET","Parameters":[],"ContentType":"application/x-www-form-urlencoded","SharedSecret":"","AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"object":{"body":"","headers":{"Accept-Encoding":"gzip","Content-Type":"text/plain","Host":"talker-api.authorino.svc.cluster.local:3000","User-Agent":"Go-http-client/1.1","Version":"HTTP/1.1"},"method":"GET","path":"/metadata","query_string":"encoding=text/plain&original_path=/hello","uuid":"46d6f76f-a7bb-41a5-ab5c-73ccde81995a"}}
{"level":"debug","ts":1634551414.250598,"logger":"metadata.uma","msg":"getting resource data","request id":"4319406766266888331","url":"http://keycloak:8080/auth/realms/kuadrant/authz/protection/resource_set/e20d194c-274c-4845-8c02-0ca413c9bf18"}
{"level":"debug","ts":1634551414.3078501,"logger":"service.authpipeline.metadata","msg":"fetched auth metadata","request id":"4319406766266888331","config":{"Name":"uma-resource-registry","UserInfo":null,"UMA":{"Endpoint":"http://keycloak:8080/auth/realms/kuadrant","ClientID":"talker-api","ClientSecret":"523b92b6-625d-4e1e-a313-77e7a8ae4e88"},"GenericHTTP":null},"object":[{"_id":"e20d194c-274c-4845-8c02-0ca413c9bf18","attributes":{},"displayName":"hello","name":"hello","owner":{"id":"57a645a5-fb67-438b-8be5-dfb971666dbc"},"ownerManagedAccess":false,"resource_scopes":[],"uris":["/hi","/hello"]}]}
{"level":"debug","ts":1634551414.3081045,"logger":"service.authpipeline.authorization","msg":"evaluating for input","request id":"4319406766266888331","input":{"context":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":37552}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"time":{"seconds":1634551413,"nanos":977636000},"http":{"id":"4319406766266888331","method":"GET","headers":{":authority":"talker-api",":method":"GET",":path":"/hello",":scheme":"http","accept":"*/*","authorization":"Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IlQtcHlkNkhxZy1IclQyQWU2R0JldXVUNjB3T3ltWEpobmdXQ1M2aUNUVlkifQ.eyJhdWQiOlsidGFsa2VyLWFwaSJdLCJleHAiOjE2MzQ1NTIwMDUsImlhdCI6MTYzNDU1MTQwNSwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXItMSIsInVpZCI6IjIzMzViMmUyLTc5YjAtNGI1OC05ZGUyLWI1OWI5NmI3ZjM2MyJ9fSwibmJmIjoxNjM0NTUxNDA1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YXV0aG9yaW5vOmFwaS1jb25zdW1lci0xIn0.cggcG0ylvXqK9Ifm2Svch8KY1rlwxqitSZ_lyujNpx_uL6NP8K4QPviOMhu9qssR8LkX11yy1oR5wlGr-1iDB-pMZ_zm7LCnzj6xoUJF79p0uV06ijTLiEOSvIge9SGDA-ERdqLqn0-SH83--Nl7kyi9mkJihGBSw3TxEZyLqP7hsWL1OpoNolR6DrUzqCswXWGBtVJnNPeLTK0SIcw1hBKL_L3DsVNKNbBtsWjZapBUCv_UD0bf49tHsqt_XPZF2p7ZIqpSvzkBN8sfWTtwdms-y9jww3WWSbOdD4eVNh4_glWcSnjfgyRTyV0rBFGsPppxWNpLvUEqnxoicXiTsg","user-agent":"curl/7.65.3","x-envoy-internal":"true","x-forwarded-for":"10.244.0.10","x-forwarded-proto":"http","x-request-id":"d84abac9-f245-4704-942d-242ae8f0a97e"},"path":"/hello","host":"talker-api","scheme":"http","protocol":"HTTP/1.1"}},"context_extensions":{"virtual_host":"local_service"},"metadata_context":{}},"auth":{"identity":{"aud":["talker-api"],"exp":1634552005,"iat":1634551405,"iss":"https://kubernetes.default.svc.cluster.local","kubernetes.io":{"namespace":"authorino","serviceaccount":{"name":"api-consumer-1","uid":"2335b2e2-79b0-4b58-9de2-b59b96b7f363"}},"nbf":1634551405,"sub":"system:serviceaccount:authorino:api-consumer-1"},"metadata":{"http-metadata":{"body":"","headers":{"Accept-Encoding":"gzip","Content-Type":"text/plain","Host":"talker-api.authorino.svc.cluster.local:3000","User-Agent":"Go-http-client/1.1","Version":"HTTP/1.1"},"method":"GET","path":"/metadata","query_string":"encoding=text/plain&original_path=/hello","uuid":"46d6f76f-a7bb-41a5-ab5c-73ccde81995a"},"uma-resource-registry":[{"_id":"e20d194c-274c-4845-8c02-0ca413c9bf18","attributes":{},"displayName":"hello","name":"hello","owner":{"id":"57a645a5-fb67-438b-8be5-dfb971666dbc"},"ownerManagedAccess":false,"resource_scopes":[],"uris":["/hi","/hello"]}]}}}}
{"level":"debug","ts":1634551414.3141236,"logger":"service.authpipeline.authorization","msg":"access granted","request id":"4319406766266888331","config":{"Name":"my-policy","OPA":{"Rego":"fail := input.context.request.http.headers[\"x-ext-auth-mock\"] == \"FAIL\"\nallow { not fail }\n","OPAExternalSource":{"Endpoint":"","SharedSecret":"","AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"JSON":null,"KubernetesAuthz":null},"object":true}
{"level":"debug","ts":1634551414.3149953,"logger":"authorization.kubernetesauthz","msg":"calling kubernetes subject access review api","request id":"4319406766266888331","subjectaccessreview":{"metadata":{"creationTimestamp":null},"spec":{"nonResourceAttributes":{"path":"/hello","verb":"get"},"user":"system:serviceaccount:authorino:api-consumer-1"},"status":{"allowed":false}}}
{"level":"debug","ts":1634551414.3286507,"logger":"service.authpipeline.authorization","msg":"access granted","request id":"4319406766266888331","config":{"Name":"kubernetes-rbac","OPA":null,"JSON":null,"KubernetesAuthz":{"Conditions":[],"User":{"Static":"","Pattern":"auth.identity.sub"},"Groups":null,"ResourceAttributes":null}},"object":true}
{"level":"debug","ts":1634551414.3328106,"logger":"service.authpipeline.response","msg":"dynamic response built","request id":"4319406766266888331","config":{"Name":"wristband","Wrapper":"httpHeader","WrapperKey":"x-ext-auth-wristband","Wristband":{"Issuer":"https://authorino-oidc.authorino.svc:8083/authorino/talker-api-protection/wristband","CustomClaims":[],"TokenDuration":300,"SigningKeys":[{"use":"sig","kty":"EC","kid":"wristband-signing-key","crv":"P-256","alg":"ES256","x":"TJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZw","y":"SSg8rKBsJ3J1LxyLtt0oFvhHvZcUpmRoTuHk3UHisTA","d":"Me-5_zWBWVYajSGZcZMCcD8dXEa4fy85zv_yN7BxW-o"}]},"DynamicJSON":null},"object":"eyJhbGciOiJFUzI1NiIsImtpZCI6IndyaXN0YmFuZC1zaWduaW5nLWtleSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzQ1NTE3MTQsImlhdCI6MTYzNDU1MTQxNCwiaXNzIjoiaHR0cHM6Ly9hdXRob3Jpbm8tb2lkYy5hdXRob3Jpbm8uc3ZjOjgwODMvYXV0aG9yaW5vL3RhbGtlci1hcGktcHJvdGVjdGlvbi93cmlzdGJhbmQiLCJzdWIiOiI3ZmQ3YTgxNjIxYjU1NzU3YmYwMDQ1N2MzNDc5MWVkYTJhYjFjMGRhYmJjODIwMDBiZmIxOGUxNjg1ZWJlZDY1In0.qwvyL4fk3GaEzeywjMOWkPyPWQI8qj_Gwv-jceecbt-ho2Kjio2YwR7Al54PtyhabyFe3tAx6e4ce1VL-_5K3w"}
{"level":"info","ts":1634551414.333159,"logger":"service.auth","msg":"outgoing authorization response","request id":"4319406766266888331","authorized":true,"response":"OK"}
{"level":"debug","ts":1634551414.3332148,"logger":"service.auth","msg":"outgoing authorization response","request id":"4319406766266888331","authorized":true,"response":"OK"}
```

#### Enforcing `AuthConfig` while authenticating with API key:

<details>
  <summary>`AuhConfig` composed of:</summary>

  - identity: k8s-auth, oidc, oauth2, apikey
  - metadata: http, oidc userinfo
  - authorization: opa, k8s-authz
  - response: wristband
</details>

```jsonc
{"level":"info","ts":1634551682.6549013,"logger":"service.auth","msg":"incoming authorization request","request id":"4401610019984596583","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":40306}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"http":{"id":"4401610019984596583","method":"GET","path":"/hello","host":"talker-api","scheme":"http"}}}}
{"level":"debug","ts":1634551682.6549954,"logger":"service.auth","msg":"incoming authorization request","request id":"4401610019984596583","object":"source:{address:{socket_address:{address:\"127.0.0.1\"  port_value:40306}}}  destination:{address:{socket_address:{address:\"127.0.0.1\"  port_value:8000}}}  request:{time:{seconds:1634551682  nanos:650878000}  http:{id:\"4401610019984596583\"  method:\"GET\"  headers:{key:\":authority\"  value:\"talker-api\"}  headers:{key:\":method\"  value:\"GET\"}  headers:{key:\":path\"  value:\"/hello\"}  headers:{key:\":scheme\"  value:\"http\"}  headers:{key:\"accept\"  value:\"*/*\"}  headers:{key:\"authorization\"  value:\"APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx\"}  headers:{key:\"user-agent\"  value:\"curl/7.65.3\"}  headers:{key:\"x-envoy-internal\"  value:\"true\"}  headers:{key:\"x-forwarded-for\"  value:\"10.244.0.10\"}  headers:{key:\"x-forwarded-proto\"  value:\"http\"}  headers:{key:\"x-request-id\"  value:\"f101f020-4177-4bfd-9da0-78ad2ae8b76e\"}  path:\"/hello\"  host:\"talker-api\"  scheme:\"http\"  protocol:\"HTTP/1.1\"}}  context_extensions:{key:\"virtual_host\"  value:\"local_service\"}  metadata_context:{}"}
{"level":"debug","ts":1634551682.655159,"logger":"service.authpipeline.identity","msg":"cannot validate identity","request id":"4401610019984596583","config":{"Name":"keycloak-opaque","ExtendedProperties":[],"OAuth2":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"TokenIntrospectionUrl":"http://keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token/introspect","TokenTypeHint":"requesting_party_token","ClientID":"talker-api","ClientSecret":"523b92b6-625d-4e1e-a313-77e7a8ae4e88"},"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":null},"reason":"credential not found"}
{"level":"debug","ts":1634551682.6554494,"logger":"service.authpipeline.identity","msg":"identity validated","request id":"4401610019984596583","config":{"Name":"api-keys","ExtendedProperties":[{"Name":"sub","Value":{"Static":null,"Pattern":"auth.identity.metadata.annotations.userid"}}],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":{"AuthCredentials":{"KeySelector":"APIKEY","In":"authorization_header"},"Name":"api-keys","LabelSelectors":{"audience":"talker-api","authorino.3scale.net/managed-by":"authorino"}},"KubernetesAuth":null},"object":{"apiVersion":"v1","data":{"api_key":"bmR5QnpyZVV6RjR6cURRc3FTUE1Ia1JocmlFT3RjUng="},"kind":"Secret","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"annotations\":{\"userid\":\"john\"},\"labels\":{\"audience\":\"talker-api\",\"authorino.3scale.net/managed-by\":\"authorino\"},\"name\":\"api-key-1\",\"namespace\":\"authorino\"},\"stringData\":{\"api_key\":\"ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx\"},\"type\":\"Opaque\"}\n","userid":"john"},"creationTimestamp":"2021-10-18T10:01:16Z","labels":{"audience":"talker-api","authorino.3scale.net/managed-by":"authorino"},"managedFields":[{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:data":{".":{},"f:api_key":{}},"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{},"f:userid":{}},"f:labels":{".":{},"f:audience":{},"f:authorino.3scale.net/managed-by":{}}},"f:type":{}},"manager":"kubectl-client-side-apply","operation":"Update","time":"2021-10-18T10:01:16Z"}],"name":"api-key-1","namespace":"authorino","resourceVersion":"82614","uid":"063b2485-8df8-4278-be1f-7a73e30f2f7c"},"sub":"john","type":"Opaque"}}
{"level":"debug","ts":1634551682.655882,"logger":"metadata.uma","msg":"requesting pat","request id":"4401610019984596583","url":"http://talker-api:523b92b6-625d-4e1e-a313-77e7a8ae4e88@keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token","data":"grant_type=client_credentials","headers":{"Content-Type":["application/x-www-form-urlencoded"]}}
{"level":"debug","ts":1634551682.656373,"logger":"service.authpipeline","msg":"skipping config","request id":"4401610019984596583","config":{"Name":"k8s-service-accounts","ExtendedProperties":[],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"reason":"context canceled"}
{"level":"debug","ts":1634551682.656505,"logger":"service.authpipeline","msg":"skipping config","request id":"4401610019984596583","config":{"Name":"keycloak-jwts","ExtendedProperties":[],"OAuth2":null,"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"},"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":null},"reason":"context canceled"}
{"level":"debug","ts":1634551682.6567788,"logger":"metadata.http","msg":"sending request","request id":"4401610019984596583","method":"GET","url":"http://talker-api.authorino.svc.cluster.local:3000/metadata?encoding=text/plain&original_path=/hello","headers":{"Content-Type":["text/plain"]}}
{"level":"debug","ts":1634551682.6572335,"logger":"service.authpipeline.metadata","msg":"cannot fetch metadata","request id":"4401610019984596583","config":{"Name":"oidc-userinfo","UserInfo":{"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"}},"UMA":null,"GenericHTTP":null},"reason":"Missing identity for OIDC issuer http://keycloak:8080/auth/realms/kuadrant. Skipping related UserInfo metadata."}
{"level":"debug","ts":1634551682.7108297,"logger":"service.authpipeline.metadata","msg":"fetched auth metadata","request id":"4401610019984596583","config":{"Name":"http-metadata","UserInfo":null,"UMA":null,"GenericHTTP":{"Endpoint":"http://talker-api.authorino.svc.cluster.local:3000/metadata?encoding=text/plain&original_path={context.request.http.path}","Method":"GET","Parameters":[],"ContentType":"application/x-www-form-urlencoded","SharedSecret":"","AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"object":{"body":"","headers":{"Accept-Encoding":"gzip","Content-Type":"text/plain","Host":"talker-api.authorino.svc.cluster.local:3000","User-Agent":"Go-http-client/1.1","Version":"HTTP/1.1"},"method":"GET","path":"/metadata","query_string":"encoding=text/plain&original_path=/hello","uuid":"4be8e2a4-dc7a-4175-8cb7-299235a5f519"}}
{"level":"debug","ts":1634551682.7590704,"logger":"metadata.uma","msg":"querying resources by uri","request id":"4401610019984596583","url":"http://keycloak:8080/auth/realms/kuadrant/authz/protection/resource_set?uri=/hello"}
{"level":"debug","ts":1634551682.8278995,"logger":"metadata.uma","msg":"getting resource data","request id":"4401610019984596583","url":"http://keycloak:8080/auth/realms/kuadrant/authz/protection/resource_set/e20d194c-274c-4845-8c02-0ca413c9bf18"}
{"level":"debug","ts":1634551682.8758085,"logger":"service.authpipeline.metadata","msg":"fetched auth metadata","request id":"4401610019984596583","config":{"Name":"uma-resource-registry","UserInfo":null,"UMA":{"Endpoint":"http://keycloak:8080/auth/realms/kuadrant","ClientID":"talker-api","ClientSecret":"523b92b6-625d-4e1e-a313-77e7a8ae4e88"},"GenericHTTP":null},"object":[{"_id":"e20d194c-274c-4845-8c02-0ca413c9bf18","attributes":{},"displayName":"hello","name":"hello","owner":{"id":"57a645a5-fb67-438b-8be5-dfb971666dbc"},"ownerManagedAccess":false,"resource_scopes":[],"uris":["/hi","/hello"]}]}
{"level":"debug","ts":1634551682.8759265,"logger":"service.authpipeline.authorization","msg":"evaluating for input","request id":"4401610019984596583","input":{"context":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":40306}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"time":{"seconds":1634551682,"nanos":650878000},"http":{"id":"4401610019984596583","method":"GET","headers":{":authority":"talker-api",":method":"GET",":path":"/hello",":scheme":"http","accept":"*/*","authorization":"APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx","user-agent":"curl/7.65.3","x-envoy-internal":"true","x-forwarded-for":"10.244.0.10","x-forwarded-proto":"http","x-request-id":"f101f020-4177-4bfd-9da0-78ad2ae8b76e"},"path":"/hello","host":"talker-api","scheme":"http","protocol":"HTTP/1.1"}},"context_extensions":{"virtual_host":"local_service"},"metadata_context":{}},"auth":{"identity":{"apiVersion":"v1","data":{"api_key":"bmR5QnpyZVV6RjR6cURRc3FTUE1Ia1JocmlFT3RjUng="},"kind":"Secret","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"annotations\":{\"userid\":\"john\"},\"labels\":{\"audience\":\"talker-api\",\"authorino.3scale.net/managed-by\":\"authorino\"},\"name\":\"api-key-1\",\"namespace\":\"authorino\"},\"stringData\":{\"api_key\":\"ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx\"},\"type\":\"Opaque\"}\n","userid":"john"},"creationTimestamp":"2021-10-18T10:01:16Z","labels":{"audience":"talker-api","authorino.3scale.net/managed-by":"authorino"},"managedFields":[{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:data":{".":{},"f:api_key":{}},"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{},"f:userid":{}},"f:labels":{".":{},"f:audience":{},"f:authorino.3scale.net/managed-by":{}}},"f:type":{}},"manager":"kubectl-client-side-apply","operation":"Update","time":"2021-10-18T10:01:16Z"}],"name":"api-key-1","namespace":"authorino","resourceVersion":"82614","uid":"063b2485-8df8-4278-be1f-7a73e30f2f7c"},"sub":"john","type":"Opaque"},"metadata":{"http-metadata":{"body":"","headers":{"Accept-Encoding":"gzip","Content-Type":"text/plain","Host":"talker-api.authorino.svc.cluster.local:3000","User-Agent":"Go-http-client/1.1","Version":"HTTP/1.1"},"method":"GET","path":"/metadata","query_string":"encoding=text/plain&original_path=/hello","uuid":"4be8e2a4-dc7a-4175-8cb7-299235a5f519"},"uma-resource-registry":[{"_id":"e20d194c-274c-4845-8c02-0ca413c9bf18","attributes":{},"displayName":"hello","name":"hello","owner":{"id":"57a645a5-fb67-438b-8be5-dfb971666dbc"},"ownerManagedAccess":false,"resource_scopes":[],"uris":["/hi","/hello"]}]}}}}
{"level":"debug","ts":1634551682.8826444,"logger":"authorization.kubernetesauthz","msg":"calling kubernetes subject access review api","request id":"4401610019984596583","subjectaccessreview":{"metadata":{"creationTimestamp":null},"spec":{"nonResourceAttributes":{"path":"/hello","verb":"get"},"user":"john"},"status":{"allowed":false}}}
{"level":"debug","ts":1634551682.8924532,"logger":"service.authpipeline.authorization","msg":"access granted","request id":"4401610019984596583","config":{"Name":"my-policy","OPA":{"Rego":"fail := input.context.request.http.headers[\"x-ext-auth-mock\"] == \"FAIL\"\nallow { not fail }\n","OPAExternalSource":{"Endpoint":"","SharedSecret":"","AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"JSON":null,"KubernetesAuthz":null},"object":true}
{"level":"debug","ts":1634551682.9139812,"logger":"service.authpipeline.authorization","msg":"access granted","request id":"4401610019984596583","config":{"Name":"kubernetes-rbac","OPA":null,"JSON":null,"KubernetesAuthz":{"Conditions":[],"User":{"Static":"","Pattern":"auth.identity.sub"},"Groups":null,"ResourceAttributes":null}},"object":true}
{"level":"debug","ts":1634551682.9142876,"logger":"service.authpipeline.response","msg":"dynamic response built","request id":"4401610019984596583","config":{"Name":"wristband","Wrapper":"httpHeader","WrapperKey":"x-ext-auth-wristband","Wristband":{"Issuer":"https://authorino-oidc.authorino.svc:8083/authorino/talker-api-protection/wristband","CustomClaims":[],"TokenDuration":300,"SigningKeys":[{"use":"sig","kty":"EC","kid":"wristband-signing-key","crv":"P-256","alg":"ES256","x":"TJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZw","y":"SSg8rKBsJ3J1LxyLtt0oFvhHvZcUpmRoTuHk3UHisTA","d":"Me-5_zWBWVYajSGZcZMCcD8dXEa4fy85zv_yN7BxW-o"}]},"DynamicJSON":null},"object":"eyJhbGciOiJFUzI1NiIsImtpZCI6IndyaXN0YmFuZC1zaWduaW5nLWtleSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzQ1NTE5ODIsImlhdCI6MTYzNDU1MTY4MiwiaXNzIjoiaHR0cHM6Ly9hdXRob3Jpbm8tb2lkYy5hdXRob3Jpbm8uc3ZjOjgwODMvYXV0aG9yaW5vL3RhbGtlci1hcGktcHJvdGVjdGlvbi93cmlzdGJhbmQiLCJzdWIiOiI0OTI1ZjBkMjY5MTFlMTU0ODYyMzRjYzVkMDE1M2JhN2NkOWY4MDc4ZjUzMjQ5MDM2Y2YzZTQ4M2VjMWJlYjllIn0.xhSAB42UGcy_toZjBvKUDZzpL8SQIjFo0FtZx0RUeikGjomocZzERmWo_Fx7gwOr4RcRNJmZotjLthwJ5cuavw"}
{"level":"info","ts":1634551682.9143596,"logger":"service.auth","msg":"outgoing authorization response","request id":"4401610019984596583","authorized":true,"response":"OK"}
{"level":"debug","ts":1634551682.9143841,"logger":"service.auth","msg":"outgoing authorization response","request id":"4401610019984596583","authorized":true,"response":"OK"}
```

#### Enforcing `AuthConfig` while authenticating with invalid API key:

<details>
  <summary>`AuhConfig` composed of:</summary>

  - identity: k8s-auth, oidc, oauth2, apikey
  - metadata: http, oidc userinfo
  - authorization: opa, k8s-authz
  - response: wristband
</details>

```jsonc
{"level":"info","ts":1634551806.164329,"logger":"service.auth","msg":"incoming authorization request","request id":"7514705783179910737","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":41506}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"http":{"id":"7514705783179910737","method":"GET","path":"/hello","host":"talker-api","scheme":"http"}}}}
{"level":"debug","ts":1634551806.1644406,"logger":"service.auth","msg":"incoming authorization request","request id":"7514705783179910737","object":"source:{address:{socket_address:{address:\"127.0.0.1\"  port_value:41506}}}  destination:{address:{socket_address:{address:\"127.0.0.1\"  port_value:8000}}}  request:{time:{seconds:1634551806  nanos:158529000}  http:{id:\"7514705783179910737\"  method:\"GET\"  headers:{key:\":authority\"  value:\"talker-api\"}  headers:{key:\":method\"  value:\"GET\"}  headers:{key:\":path\"  value:\"/hello\"}  headers:{key:\":scheme\"  value:\"http\"}  headers:{key:\"accept\"  value:\"*/*\"}  headers:{key:\"authorization\"  value:\"APIKEY invalid\"}  headers:{key:\"user-agent\"  value:\"curl/7.65.3\"}  headers:{key:\"x-envoy-internal\"  value:\"true\"}  headers:{key:\"x-forwarded-for\"  value:\"10.244.0.10\"}  headers:{key:\"x-forwarded-proto\"  value:\"http\"}  headers:{key:\"x-request-id\"  value:\"ddb5f31c-1959-4228-9d12-e4895f2fcf25\"}  path:\"/hello\"  host:\"talker-api\"  scheme:\"http\"  protocol:\"HTTP/1.1\"}}  context_extensions:{key:\"virtual_host\"  value:\"local_service\"}  metadata_context:{}"}
{"level":"debug","ts":1634551806.1696699,"logger":"service.authpipeline.identity","msg":"cannot validate identity","request id":"7514705783179910737","config":{"Name":"keycloak-opaque","ExtendedProperties":[],"OAuth2":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"TokenIntrospectionUrl":"http://keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token/introspect","TokenTypeHint":"requesting_party_token","ClientID":"talker-api","ClientSecret":"523b92b6-625d-4e1e-a313-77e7a8ae4e88"},"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":null},"reason":"credential not found"}
{"level":"debug","ts":1634551806.177158,"logger":"service.authpipeline.identity","msg":"cannot validate identity","request id":"7514705783179910737","config":{"Name":"api-keys","ExtendedProperties":[{"Name":"sub","Value":{"Static":null,"Pattern":"auth.identity.metadata.annotations.userid"}}],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":{"AuthCredentials":{"KeySelector":"APIKEY","In":"authorization_header"},"Name":"api-keys","LabelSelectors":{"audience":"talker-api","authorino.3scale.net/managed-by":"authorino"}},"KubernetesAuth":null},"reason":"the API Key provided is invalid"}
{"level":"debug","ts":1634551806.177641,"logger":"service.authpipeline.identity","msg":"cannot validate identity","request id":"7514705783179910737","config":{"Name":"k8s-service-accounts","ExtendedProperties":[],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"reason":"credential not found"}
{"level":"debug","ts":1634551806.1777687,"logger":"service.authpipeline.identity","msg":"cannot validate identity","request id":"7514705783179910737","config":{"Name":"keycloak-jwts","ExtendedProperties":[],"OAuth2":null,"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"},"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":null},"reason":"credential not found"}
{"level":"info","ts":1634551806.1780047,"logger":"service.auth","msg":"outgoing authorization response","request id":"7514705783179910737","authorized":false,"response":"UNAUTHENTICATED","object":{"code":16,"status":302,"message":"Redirecting to login"}}
{"level":"debug","ts":1634551806.1782873,"logger":"service.auth","msg":"outgoing authorization response","request id":"7514705783179910737","authorized":false,"response":"UNAUTHENTICATED","object":{"code":16,"status":302,"message":"Redirecting to login","headers":[{"Location":"https://my-app.io/login"}]}}
```

#### Deleting `AuthConfig` and related API key `Secret`s:

```jsonc
{"level":"info","ts":1634551854.9367976,"logger":"controller-runtime.manager.controller.authconfig","msg":"object has been deleted, deleted related configs","authconfig":"authorino/talker-api-protection"}
{"level":"info","ts":1634551854.9991832,"logger":"controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"authorino/api-key-1"}
{"level":"info","ts":1634551855.0298505,"logger":"controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"authorino/api-key-2"}
```

#### Shutting down the service:

```jsonc
{"level":"info","ts":1634550405.638155,"logger":"controller-runtime.manager.controller.authconfig","msg":"Shutdown signal received, waiting for all workers to finish","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig"}
{"level":"info","ts":1634550405.6434295,"logger":"controller-runtime.manager.controller.authconfig","msg":"All workers finished","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig"}
{"level":"info","ts":1634550405.641585,"logger":"controller-runtime.manager.controller.secret","msg":"Shutdown signal received, waiting for all workers to finish","reconciler group":"","reconciler kind":"Secret"}
{"level":"info","ts":1634550405.6477098,"logger":"controller-runtime.manager.controller.secret","msg":"All workers finished","reconciler group":"","reconciler kind":"Secret"}
{"level":"info","ts":1634550405.6411886,"logger":"controller-runtime.manager.controller.authconfig","msg":"Shutdown signal received, waiting for all workers to finish","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig"}
{"level":"info","ts":1634550405.6477563,"logger":"controller-runtime.manager.controller.authconfig","msg":"All workers finished","reconciler group":"authorino.3scale.net","reconciler kind":"AuthConfig"}
```
