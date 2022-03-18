# User guides

- **[Hello World](./user-guides/hello-world.md)**<br/>
The basics of protecting an API with Authorino.

- **[Authentication with Kubernetes tokens (TokenReview API)](./user-guides/kubernetes-tokenreview.md)**<br/>
Validate Kubernetes Service Account tokens to authenticate requests to your protected hosts.

- **[Authentication with API keys](./user-guides/api-key-authentication.md)**<br/>
Issue API keys stored in Kubernetes `Secret`s for clients to authenticate with your protected hosts.

- **[OpenID Connect Discovery and authentication with JWTs](./user-guides/oidc-jwt-authentication.md)**<br/>
Validate JSON Web Tokens (JWT) issued and signed by an OpenID Connect server; leverage OpenID Connect Discovery to automatically fetch JSON Web Key Sets (JWKS).

- **[OAuth 2.0 token introspection (RFC 7662)](./user-guides/oauth2-token-introspection.md)**<br/>
Introspect OAuth 2.0 access tokens (e.g. opaque tokens) for online user data and token validation in request-time.

- **[Passing credentials (`Authorization` header, cookie headers and others)](./user-guides/passing-credentials.md)**<br/>
Customize where credentials are supplied in the request by each trusted source of identity.

- **[HTTP "Basic" Authentication (RFC 7235)](./user-guides/http-basic-authentication.md)**<br/>
Turn Authorino API key `Secret`s settings into HTTP basic auth.

- **[Anonymous access](./user-guides/anonymous-access.md)**<br/>
Bypass identity verification or fall back to anonymous access when credentials fail to validate

- **[Token normalization](./user-guides/token-normalization.md)**<br/>
Normalize identity claims from trusted sources and reduce complexity in your policies.

- **[Edge Authentication Architecture (EAA)](./user-guides/edge-authentication-architecture-festival-wristbands.md)**<br/>
Exchange satellite (outer-layer) authentication tokens for "Festival Wristbands" accepted ubiquitously at the inside of your network. Normalize from multiple and varied sources of identity and authentication methods in the edge of your architecture; filter privacy data, limit the scope of permissions, and simplify authorization rules to your internal micro-services.

- **[Fetching auth metadata from external sources](./user-guides/external-metadata.md)**<br/>
Get online data from remote HTTP services to enhance authorization rules.

- **[OpenID Connect UserInfo](./user-guides/oidc-user-info.md)**<br/>
Fetch user info for OpenID Connect ID tokens in request-time for extra metadata for your policies and online verification of token validity.

- **[Resource-level authorization with User-Managed Access (UMA) resource registry](./user-guides/resource-level-authorization-uma.md)**<br/>
Fetch resource attributes relevant for authorization from a User-Managed Access (UMA) resource registry such as Keycloak resource server clients.

- **[Simple pattern-matching authorization policies](./user-guides/json-pattern-matching-authorization.md)**<br/>
Write simple authorization rules based on JSON patterns matched against Authorino's Authorization JSON; check contextual information of the request, validate JWT claims, cross metadata fetched from external sources, etc.

- **[OpenID Connect (OIDC) and Role-Based Access Control (RBAC) with Authorino and Keycloak](./user-guides/oidc-rbac.md)**<br/>
Combine OpenID Connect (OIDC) authentication and Role-Based Access Control (RBAC) authorization rules leveraging Keycloak and Authorino working together.

- **[Open Policy Agent (OPA) Rego policies](./user-guides/opa-authorization.md)**<br/>
Leverage the power of Open Policy Agent (OPA) policies, evaluated against Authorino's Authorization JSON in a built-in runtime compiled together with Authorino; pre-cache policies defined in Rego language inline or fetched from an external policy registry.

- **[Kubernetes RBAC for service authorization (SubjectAccessReview API)](./user-guides/kubernetes-subjectaccessreview.md)**<br/>
Manage permissions in the Kubernetes RBAC and let Authorino to check them in request-time with the authorization system of the cluster.

- **[Injecting data in the request](./user-guides/injecting-data.md)**<br/>
Inject HTTP headers with serialized JSON content.

- **[Authenticated rate limiting (with Envoy Dynamic Metadata)](./user-guides/authenticated-rate-limiting-envoy-dynamic-metadata.md)**<br/>
Provide Envoy with dynamic metadata from the external authorization process to be injected and used by consecutive filters, such as by a rate limiting service.

- **[Redirecting to a login page](./user-guides/deny-with-redirect-to-login.md)**<br/>
Customize response status code and headers on failed requests. E.g. redirect users of a web application protected with Authorino to a login page instead of a `401 Unauthorized`; mask resources on access denied behind a `404 Not Found` response instead of `403 Forbidden`.

- **[Host override via context extension](./user-guides/host-override.md)**<br/>
Induce the lookup of an AuthConfig by supplying extended host context, for use cases such as of path prefix-based lookup and wildcard subdomains lookup.

- **[Reducing the operational space: sharding, noise and multi-tenancy](./user-guides/sharding.md)**<br/>
Have multiple instances of Authorino running in the same space (Kubernetes namespace or cluster-scoped), yet watching particular sets of resources.

- **[Observability](./user-guides/metrics.md)**<br/>
Prometheus metrics exported by Authorino.

- **[Logging](./user-guides/logging.md)**<br/>
Parse Authorino's structured JSON log messages; activate debug log level and get more user-friendly outputs in dev environment.

- **[Tracing](./user-guides/logging.md#3-tracing-id)**<br/>
Trace authorization requests deep across the stack.
