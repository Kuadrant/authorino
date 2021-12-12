# Features

- [Overview](#overview)
- [Common feature: JSON paths (`valueFrom.authJSON`)](#common-feature-json-paths-valuefromauthjson)
  - [Syntax](#syntax)
  - [String modifiers](#string-modifiers)
  - [Interpolation](#interpolation)
- [Identity verification & authentication features (`identity`)](#identity-verification--authentication-features-identity)
  - [API key (`identity.apiKey`)](#api-key-identityapikey)
  - [Kubernetes TokenReview (`identity.kubernetes`)](#kubernetes-tokenreview-identitykubernetes)
  - [OpenID Connect (OIDC) JWT/JOSE verification and validation (`identity.oidc`)](#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc)
  - [OAuth 2.0 introspection (`identity.oauth2`)](#oauth-20-introspection-identityoauth2)
  - [OpenShift OAuth (user-echo endpoint) (`identity.openshift`)](#openshift-oauth-user-echo-endpoint-identityopenshift)
  - [Mutual Transport Layer Security (mTLS) authentication (`identity.mtls`)](#mutual-transport-layer-security-mtls-authentication-identitymtls)
  - [Hash Message Authentication Code (HMAC) authentication (`identity.hmac`)](#hash-message-authentication-code-hmac-authentication-identityhmac)
  - [Festival Wristband authentication](#festival-wristband-authentication)
  - [_Extra:_ Auth credentials (`credentials`)](#extra-auth-credentials-credentials)
  - [_Extra:_ Identity extension (`extendedProperties`)](#extra-identity-extension-extendedproperties)
- [External auth metadata features (`metadata`)](#external-auth-metadata-features-metadata)
  - [HTTP GET/GET-by-POST (`metadata.http`)](#http-getget-by-post-metadatahttp)
  - [OIDC UserInfo (`metadata.userInfo`)](#oidc-userinfo-metadatauserinfo)
  - [User-Managed Access (UMA) resource registry (`metadata.uma`)](#user-managed-access-uma-resource-registry-metadatauma)
- [Authorization features (`authorization`)](#authorization-features-authorization)
  - [JSON pattern-matching authorization rules (`authorization.json`)](#json-pattern-matching-authorization-rules-authorizationjson)
  - [Open Policy Agent (OPA) Rego policies (`authorization.opa`)](#open-policy-agent-opa-rego-policies-authorizationopa)
  - [Kubernetes SubjectAccessReview (`authorization.kubernetes`)](#kubernetes-subjectaccessreview-authorizationkubernetes)
  - [Keycloak Authorization Services (UMA-compliant Authorization API)](#keycloak-authorization-services-uma-compliant-authorization-api)
- [Dynamic response features (`response`)](#dynamic-response-features-response)
  - [JSON injection (`response.json`)](#json-injection-responsejson)
  - [Festival Wristband tokens (`response.wristband`)](#festival-wristband-tokens-responsewristband)
  - [_Extra:_ Response wrappers (`wrapper` and `wrapperKey`)](#extra-response-wrappers-wrapper-and-wrapperkey)
    - [Added HTTP headers](#added-http-headers)
    - [Envoy Dynamic Metadata](#envoy-dynamic-metadata)
  - [_Extra:_ Custom denial status (`denyWith`)](#extra-custom-denial-status-denywith)
- [Common feature: Priorities](#common-feature-priorities)

## Overview

We call _features_ of Authorino the different things one can do to enforce identity verification & authentication and authorization on requests against protected services. These can be a specific identity verification method based on a supported authentication protocol, or a method to fetch additional auth metadata in request-time, etc.

Most features of Authorino relate to the different phases of the [Auth Pipeline](./architecture.md#the-auth-pipeline) and therefore are configured in the Authorino [`AuthConfig`](./architecture.md#the-authorino-authconfig-custom-resource-definition-crd). An _identity verification feature_ usually refers to a functionality of Authorino such as the [API key-based authentication](#api-key-identityapikey) implemented by Authorino, the [validation of JWTs/OIDC ID tokens](#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc), and authentication based on [Kubernetes TokenReviews](#kubernetes-tokenreview-identitykubernetes). Analogously, [OPA](#open-policy-agent-opa-rego-policies-authorizationopa), [JSON pattern-matching](#json-pattern-matching-authorization-rules-authorizationjson) and [Kuberentes SubjectAccessReview](#kubernetes-subjectaccessreview-authorizationkubernetes) are examples of _authorization features_ of Authorino.

At a deeper level, a _feature_ can also be an additional funcionality within a bigger feature, usually applicable to the whole class the bigger feature belongs to. For instance, the configuration of the location and key selector of [auth credentials](#extra-auth-credentials-credentials), available for all identity verification-related features. Other examples would be [_Identity extension_](#extra-identity-extension-extendedproperties) and [_Response wrappers_](#extra-response-wrappers-wrapper-and-wrapperkey).

A full specification of all features of Authorino that can be configured in an `AuthConfig` can be found in the official [spec](../install/crd/authorino.3scale.net_authconfigs.yaml) of the custom resource definition.

You can also learn about Authorino features by using the [`kubectl explain`](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#explain) command in a Kubernetes cluster where the Authorino CRD has been installed. E.g. `kubectl explain authconfigs.spec.identity.extendedProperties`.

## Common feature: JSON paths ([`valueFrom.authJSON`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#ValueFromAuthJSON))

The first feature of Authorino to learn about is a common functionality, used in the specification of many other features. _JSON paths_ have to do with reading data from the [Authorization JSON](./architecture.md#the-authorization-json), to refer to them in configuration of dynamic steps of API protection enforcing.

Usage examples of JSON paths are: dynamic URL and request parameters when fetching metadata from external sources, dynamic authorization policy rules, and dynamic authorization responses (injected JSON and Festival Wristband token claims).

### Syntax

The syntax to fetch data from the Authorization JSON with JSON paths is based on [GJSON](https://pkg.go.dev/github.com/tidwall/gjson). Refer to [GJSON Path Syntax](https://github.com/tidwall/gjson/blob/master/SYNTAX.md) page for more information.

### String modifiers

On top of GJSON, Authorino defines a few [string modifiers](https://github.com/tidwall/gjson/blob/master/SYNTAX.md#modifiers).

Examples below provided for the following Authorization JSON:

```jsonc
{
  "context": {
    "request": {
      "http": {
        "path": "/pets/123",
        "headers": {
          "authorization": "Basic amFuZTpzZWNyZXQK" // jane:secret
        }
      }
    }
  },
  "auth": {
    "identity": {
      "username": "jane",
      "fullname": "Jane Smith"
    },
  },
}
```

**`@case:upper|lower`**<br/>
Changes the case of a string. E.g. `auth.identity.username.@case:upper` → `"JANE"`.

**`@replace:{"old":string,"new":string}`**<br/>
Replaces a substring within a string. E.g. `auth.identity.username.@replace:{"old":"Smith","new":"Doe"}` → `"Jane Doe"`.

**`@extract:{"sep":string,"pos":int}`**<br/>
Splits a string at occurrences of a separator (default: `" "`) and selects the substring at the `pos`-th position (default: `0`). E.g. `context.request.path.@extract:{"sep":"/","pos":2}` → `123`.

**`@base64:encode|decode`**<br/>
base64-encodes or decodes a string value. E.g. `auth.identity.username.decoded.@base64:encode` → `"amFuZQo="`.<br/>

In combination with `@extract`, `@base64` can be used to extract the username in an HTTP Basic Authentication request. E.g. `context.request.headers.authorization.@extract:{"pos":1}|@base64:decode|@extract:{"sep":":","pos":1}` → `"jane"`.

### Interpolation

_JSON paths_ can be interpolated into strings to build template-like dynamic values. E.g. `"Hello, {auth.identity.name}!"`.

## Identity verification & authentication features ([`identity`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Identity))

### API key ([`identity.apiKey`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Identity_APIKey))

Authorino relies on Kubernetes `Secret` resources to represent API keys. To define an API key, create a `Secret` in the cluster containing an `api_key` entry that holds the value of the API key.

The resource must include a label that matches Authorino's bootstrap configuration `SECRET_LABEL_SELECTOR` (default: `authorino.3scale.net/managed-by=authorino`), otherwise changes related to the resource will be ignored by the reconciler.

The resource must be labeled with the same labels specified in `spec.identity.apiKey.labelSelectors` in the `AuthConfig` custom resource. For example:

For the following `AuthConfig` CR:

```yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: my-api-protection
spec:
  hosts:
    - my-api.io
  identity:
    - name: api-key-users
      apiKey:
        labelSelectors: # the key-value set used to select the matching `Secret`s; resources including these labels will be acepted as valid API keys to authenticate to this service
          group: friends # some custom label
```

The following secret would represent a valid API key:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: user-1-api-key-1
  labels:
    authorino.3scale.net/managed-by: authorino # required, so the Authorino controller reconciles events related to this secret
    group: friends
stringData:
  api_key: <some-randomly-generated-api-key-value>
type: Opaque
```

The resolved identity object, added to the authorization JSON following an API key identity source evaluation, is the Kubernetes `Secret` resource (as JSON).

### Kubernetes TokenReview ([`identity.kubernetes`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Identity_KubernetesAuth))

Authorino can verify Kubernetes-valid access tokens (using Kubernetes [TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1) API).

These tokens can be either `ServiceAccount` tokens such as the ones issued by kubelet as part of Kubernetes [Service Account Token Volume Projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection), or any valid user access tokens issued to users of the Kubernetes server API.

The list of `audiences` of the token must include the requested host and port of the protected API (default), or all audiences specified in the Authorino `AuthConfig` custom resource. For example:

For the following `AuthConfig` CR, the Kubernetes token must include the audience `my-api.io`:

```yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: my-api-protection
spec:
  hosts:
    - my-api.io
  identity:
    - name: cluster-users
      kubernetes: {}
```

Whereas for the following `AuthConfig` CR, the Kubernetes token audiences must include **foo** and **bar**:

```yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: my-api-protection
spec:
  hosts:
    - my-api.io
  identity:
    - name: cluster-users
      kubernetes:
        audiences:
          - foo
          - bar
```

The resolved identity object, added to the authorization JSON following a Kubernetes authentication identity source evaluation, is the decoded JWT when the Kubernetes token is a valid JWT, or the value of `status.user` in the response to the TokenReview request (see Kubernetes [UserInfo](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#userinfo-v1-authentication-k8s-io) for details).

### OpenID Connect (OIDC) JWT/JOSE verification and validation ([`identity.oidc`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Identity_OidcConfig))

In reconciliation-time, using [OpenID Connect Discovery well-known endpoint](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig), Authorino automatically discovers and caches OpenID Connect configurations and associated JSON Web Key Sets (JWKS) for all OpenID Connect issuers declared in an `AuthConfig`. Then, in request-time, Authorino verifies the JSON Web Signature (JWS) and check the time validity of signed JSON Web Tokens (JWT) supplied on each request.

_Important!_ Authorino does **not** implement [OAuth2 grants](https://datatracker.ietf.org/doc/html/rfc6749#section-4) nor [OIDC authentication flows](https://openid.net/specs/openid-connect-core-1_0.html#Authentication). As a common recommendation of good practice, obtaining and refreshing access tokens is for clients to negotiate directly with the auth servers and token issuers. Authorino will only validate those tokens using the parameters provided by the trusted issuer authorities.

![OIDC](http://www.plantuml.com/plantuml/png/XO_1IWD138RlynIX9mLt7s1XfQANseDGnPx7sMmtE9EqcOpQjtUeWego7aF-__lubzcyMadHvMVYlLUV80bBc5GIWcb1v_eUDXY40qNoHiADKNtslRigDeaI2pINiBXRtLp3AkU2ke0EJkT0ESWBwj7zV3UryDNkO8inDckMLuPg6cddM0mXucWT11ycd9TjyF0X3AYM_v7TRjVtl_ckRTlFiOU2sVvU-PtpY4hZiU8U8DEElHN5cRIFD7Z3K_uCt_ONm4_ZkLiY3oN5Tm00)

The `kid` claim stated in the JWT header must match one of the keys cached by Authorino during OpenID Connect Discovery, therefore supporting JWK rotation.

The decoded payload of the validated JWT is appended to the authorization JSON as the resolved identity.

Users can control the refreshing frequency of OpenID Connect configurations by setting the `identity.oidc.ttl` field.

For an excellent summary of the underlying concepts and standards that relate OpenID Connect and JSON Object Signing and Encryption (JOSE), see this [article](https://access.redhat.com/blogs/766093/posts/1976593) by Jan Rusnacko. For official specification and RFCs, see [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), [JSON Web Token (JWT) (RFC7519)](https://datatracker.ietf.org/doc/html/rfc7519), and [JSON Object Signing and Encryption (JOSE)](http://www.iana.org/assignments/jose/jose.xhtml).

### OAuth 2.0 introspection ([`identity.oauth2`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Identity_OAuth2Config))

For bare OAuth 2.0 implementations, Authorino can perform token introspection on the access tokens supplied in the requests to protected APIs.

Authorino does not implement any of OAuth 2.0 grants for the applications to obtain the token. However, it can verify supplied tokens with the OAuth server, including opaque tokens, as long as the server exposes the `token_introspect` endpoint ([RFC 7662](https://tools.ietf.org/html/rfc7662)).

Developers must set the token introspection endpoint in the `AuthConfig`, as well as a reference to the Kubernetes secret storing the credentials of the OAuth client to be used by Authorino when requesting the introspect.

![OAuth 2.0 Token Introspect](http://www.plantuml.com/plantuml/png/NP1DJiD038NtSmehQuQgsr4R5TZ0gXLaHwHgD779g8aTF1xAZv0u3GVZ9BHH18YbttkodxzLKY-Q-ywaVQJ1Y--XP-BG2lS8AXcDkRSbN6HjMIAnWrjyp9ZK_4Xmz8lrQOI4yeHIW8CRKk4qO51GtYCPOaMG-D2gWytwhe9P_8rSLzLcDZ-VrtJ5f4XggvS17VXXw6Bm6fbcp_PmEDWTIs-pT4Y16sngccgyZY47b-W51HQJRqCNJ-k2O9FAcceQsomNsgBr8M1ATbJAoTdgyV2sZQJBHKueji5T96nAy-z5-vSAE7Y38gbNBDo8xGo-FZxXtQoGcYFVRm00)

The response returned by the OAuth2 server to the token introspection request is the the resolved identity appended to the authorization JSON.

### OpenShift OAuth (user-echo endpoint) (`identity.openshift`)

<table>
  <tr>
    <td><small>Not implemented - In analysis</small></td>
  </tr>
</table>

Online token introspection of OpenShift-valid access tokens based on OpenShift's user-echo endpoint.

### Mutual Transport Layer Security (mTLS) authentication (`identity.mtls`)

<table>
  <tr>
    <td><small>Not implemented - Planned (<a href="https://github.com/kuadrant/authorino/issues/8">#8</a>)</small></td>
  </tr>
</table>

Authentication based on client X509 certificates presented on the request to the protected APIs.

### Hash Message Authentication Code (HMAC) authentication (`identity.hmac`)

<table>
  <tr>
    <td><small>Not implemented - Planned (<a href="https://github.com/kuadrant/authorino/issues/9">#9</a>)</small></td>
  </tr>
</table>

Authentication based on the validation of a hash code generated from the contextual information of the request to the protected API, concatenated with a secret known by the API consumer.

### Festival Wristband authentication

Authorino-issued [Festival Wristband](#festival-wristband-tokens-responsewristband) tokens can be validated as any other signed JWT using Authorino's [OpenID Connect (OIDC) JWT/JOSE verification and validation](#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc).

The value of the issuer must be the same issuer specified in the custom resource for the protected API originally issuing wristband. Eventually, this can be the same custom resource where the wristband is configured as a valid source of identity, but not necessarily.

### _Extra:_ Auth credentials ([`credentials`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Credentials))

All the identity verification methods supported by Authorino can be configured regarding the location where access tokens and credentials (i.e. authentication secrets) fly within the request.

By default, authentication secrets are expected to be supplied in the `Authorization` HTTP header, with the `Bearer` prefix and plain authentication secret, separated by space. The full list of supported options for the location of authentication secrets and selector is specified in the table below:

| Location (`credentials.in`) | Description                  | Selector (`credentials.keySelector`)             |
| --------------------------- | ---------------------------- | ------------------------------------------------ |
| `authorization_header`      | `Authorization` HTTP header  | Prefix (default: `Bearer`)                       |
| `custom_header`             | Custom HTTP header           | Name of the header. Value should have no prefix. |
| `query`                     | Query string parameter       | Name of the parameter                            |
| `cookie`                    | Cookie header                | ID of the cookie entry                           |

### _Extra:_ Identity extension ([`extendedProperties`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Identity))

Resolved identity objects can be extended with user-defined JSON properties. Values can be static or fetched from the Authorization JSON

A typical use-case for this feature is token normalization. Say you have more than one identity source listed in the your `AuthConfig` but each source issues an access token with a different JSON structure – e.g. two OIDC issuers that use different names for custom JWT claims of similar meaning; when two different identity verification/authentication methods are combined, such as API keys (whose identity objects are the corresponding Kubernetes `Secret`s) and Kubernetes tokens (whose identity objects are Kubernetes UserInfo data).

In such cases, identity extension can be used to normalize the token so it always includes the same set of JSON properties of interest, regardless of the source of identity that issued the original token verified by Authorino. This simplifies the writing of authorization policies and configuration of dynamic responses.

## External auth metadata features ([`metadata`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Metadata))

### HTTP GET/GET-by-POST ([`metadata.http`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Metadata_GenericHTTP))

Generic HTTP adapter that sends a request to an external service. It can be used to fetch external metadata for the authorization policies (phase ii of the Authorino [Auth Pipeline](./architecture.md#the-auth-pipeline)), or as a web hook.

The adapter allows issuing requests either by GET or POST methods; in both cases with URL and parameters defined by the user in the spec. Dynamic values fetched from the Authorization JSON can be used.

POST request parameters as well as the encoding of the content can be controlled using the `bodyParameters` and `contentType` fields of the config, respectively. The Content-Type of POST requests can be either `application/x-www-form-urlencoded` (default) or `application/json`.

A shared secret between Authorino and the external HTTP service can be defined (see `sharedSecretRef` field), and the  service can use such secret to authenticate the origin of the request. The location where the secret travels in the request performed by Authorino to the HTTP service can be specified in a typical [`credentials`](#extra-auth-credentials-credentials) field.

Custom headers can be set with the `headers` field. Nevertheless, headers such as `Content-Type` and `Authorization` (or eventual custom header used for carrying the authentication secret, set instead via the `credentials` option) will be superseded by the respective values defined for the fields `contentType` and `sharedSecretRef`.

### OIDC UserInfo ([`metadata.userInfo`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Metadata_UserInfo))

Online fetching of OpenID Connect (OIDC) UserInfo data (phase ii of the Authorino [Auth Pipeline](./architecture.md#the-auth-pipeline)), associated with an OIDC identity source configured and resolved in phase (i).

Apart from possibly complementing information of the JWT, fetching OpenID Connect UserInfo in request-time can be particularly useful for remote checking the state of the session, as opposed to only verifying the JWT/JWS offline.

Implementation requires an OpenID Connect issuer ([`spec.identity.oidc`](#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc)) configured in the same `AuthConfig`.

The response returned by the OIDC server to the UserInfo request is appended (as JSON) to `auth.metadata` in the authorization JSON.

### User-Managed Access (UMA) resource registry ([`metadata.uma`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Metadata_UMA))

User-Managed Access (UMA) is an OAuth-based protocol for resource owners to allow other users to access their resources. Since the UMA-compliant server is expected to know about the resources, Authorino includes a client that fetches resource data from the server and adds that as metadata of the authorization payload.

This enables the implementation of resource-level Attribute-Based Access Control (ABAC) policies. Attributes of the resource fetched in a UMA flow can be, e.g., the owner of the resource, or any business-level attributes stored in the UMA-compliant server.

A UMA-compliant server is an external authorization server (e.g., Keycloak) where the protected resources are registered. It can be as well the upstream API itself, as long as it implements the UMA protocol, with initial authentication by `client_credentials` grant to exchange for a Protected API Token (PAT).

![UMA](http://www.plantuml.com/plantuml/png/ZOx1IWCn48RlUOgX9pri7w0GxOBYGGGj5G_Y8QHJTp2PgPE9qhStmhBW9NWSvll__ziM2ser9rS-Y4z1GuOiB75IoGYc5Ptp7dOOXICb2aR2Wr5xUk_6QfCeiS1m1QldXn4AwXVg2ZRmUzrGYTBki_lp71gzH1lwWYaDzopV357uIE-EnH0I7cq3CSG9dLklrxF9PyLY_rAOMNWSzts11dIBdYhg6HIBL8rOuEAwAlbJiEcoN_pQj9VOMtVZxdQ_BFHBTpC5Xs31RP4FDQSV)

It's important to notice that Authorino does NOT manage resources in the UMA-compliant server. As shown in the flow above, Authorino's UMA client is only to fetch data about the requested resources. Authorino exchanges client credentials for a Protected API Token (PAT), then queries for resources whose URI match the path of the HTTP request (as passed to Authorino by the Envoy proxy) and fetches data of each macthing resource.

The resources data is added as metadata of the authorization payload and passed as input for the configured authorization policies. All resources returned by the UMA-compliant server in the query by URI are passed along. They are available in the PDPs (authorization payload) as `input.auth.metadata.custom-name => Array`. (See [The "Auth Pipeline"](./architecture.md#the-auth-pipeline) for details.)

## Authorization features ([`authorization`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Authorization))

### JSON pattern-matching authorization rules ([`authorization.json`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Authorization_JSONPatternMatching))

Grant/deny access based on simple pattern-matching rules comparing values from the Authorization JSON.

Values can be selected from the authorization JSON built throughout the auth pipeline and operations include relational operators _equals_ (`eq`), _not equal_ (`neq`), _includes_ (`incl`; for arrays), _excludes_ (`excl`; for arrays) and _matches_ (`matches`; for regular expressions).

A typical configuration contains a `conditions` array and a `rules` array, and looks like the following:

```yaml
authorization:
  - name: my-simple-json-pattern-matching-policy
    json:
      conditions: # (Optional) Allows to establish conditions for the policy to be enforced or skipped
        - selector: context.request.http.method
          operator: eq # Other operators include neq, incl, excl, matches
          value: DELETE
      rules: # All rules must match for access to be granted
        - selector: auth.identity.group
          operator: incl
          value: admin
```

Individuals policies can be optionally skipped based on `conditions` represented with similar data selectors and operators.

### Open Policy Agent (OPA) Rego policies ([`authorization.opa`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Authorization_OPA))

You can model authorization policies in [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) and add them as part of the protection of your APIs.

Policies can be either declared in-line (in Rego language) or as an HTTP endpoint where Authorino will fetch the source code of the policy in reconciliation-time.

Authorino's built-in OPA module precompiles the policies in reconciliation-time and cache them for fast evaluation in request-time, where they receive the Authorization JSON as input.

![OPA](http://www.plantuml.com/plantuml/png/ZSv1IiH048NXVPsYc7tYVY0oeuYB0IFUeEcKfh2xAdPUATxUB4GG5B9_F-yxhKWDKGkjhsfBQgboTVCyDw_2Q254my1Fajso5arGjmvQXOU1pe7PcvfpTys7cz22Jet7n_E1ZrlqeYkayU95yoVz7loPt7fTjCX_nPRyN98vX8iyuyWvvLc8-hx_rhw5hDZ9l1Vmv3cg6FX3CRFQ4jZ3lNjF9H9sURVvUBbw62zq4fkYbYy0)

### Kubernetes SubjectAccessReview ([`authorization.kubernetes`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Authorization_KubernetesAuthz))

Access control enforcement based on rules defined in the Kubernetes authorization system (e.g. as `ClusterRole` and `ClusterRoleBinding` resources of Kubernetes RBAC authorization).

Authorino issues a [SubjectAccessReview](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1) inquiry checking with the underlying Kubernetes cluster whether the user can access the requested API resouce. It can be used with `resourceAttributes` or `nonResourceAttributes` (the latter inferring HTTP verb and method from the original request).

A Kubernetes authorization policy config looks like the following in an Authorino `AuthConfig`:

```yaml
authorization:
  - name: kubernetes-rbac
    kubernetes:
      user:
        valueFrom: # It can be a fixed value as well, by using `value` instead
          authJSON: auth.identity.metadata.annotations.userid

      groups: [] # User groups to test for.

      resourceAttributes: # Omit it to perform a non-resource `SubjectAccessReview` based on the request's path and method (verb) instead
        namespace: # other supported resource attributes are: group, resource, name, subresource and verb
          value: default

      conditions: [] # Allows to establish conditions for the policy to be enforced or skipped
```

`user` and `resourceAttributes` can be specified as a fixed value or patterns to fetch from the Authorization JSON.

An array of required `groups` can as well be specified and it will be used in the `SubjectAccessReview`.

`conditions` works exactly like in [JSON pattern-matching authorization](#json-pattern-matching-authorization-rules-authorizationjson). It allows to specify conditions for the policy to be enforced or skipped, based on values of the Authorization JSON.

### Keycloak Authorization Services (UMA-compliant Authorization API)

<table>
  <tr>
    <td><small>Not implemented - In analysis</small></td>
  </tr>
</table>

Online delegation of authorization to a Keycloak server.

## Dynamic response features ([`response`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Response))

### JSON injection ([`response.json`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Response_DynamicJSON))

User-defined dynamic JSON objects generated by Authorino in the response phase, from static or dynamic data of the auth pipeline, and passed back to the external authorization client within added HTTP headers or as Envoy [Well Known Dynamic Metadata](https://www.envoyproxy.io/docs/envoy/latest/configuration/advanced/well_known_dynamic_metadata).

The following Authorino `AuthConfig` custom resource is an example that defines 3 dynamic JSON response items, where two items are returned to the client, stringified, in added HTTP headers, and the third is wrapped as Envoy Dynamic Metadata("emitted", in Envoy terminology). Envoy proxy can be configured to "pipe" dynamic metadata emitted by one filter into another filter – for example, from external authorization to rate limit.

```yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  namespace: my-namespace
  name: my-api-protection
spec:
  hosts:
    - my-api.io
  identity:
    - name: edge
      apiKey:
        labelSelectors:
          authorino.3scale.net/managed-by: authorino
      credentials:
        in: authorization_header
        keySelector: APIKEY
  response:
    - name: a-json-returned-in-a-header
      wrapper: httpHeader # can be omitted
      wrapperKey: x-my-custom-header # if omitted, name of the header defaults to the name of the config ("a-json-returned-in-a-header")
      json:
        properties:
          - name: prop1
            value: value1
          - name: prop2
            valueFrom:
              authJSON: some.path.within.auth.json

    - name: another-json-returned-in-a-header
      wrapperKey: x-ext-auth-other-json
      json:
        properties:
          - name: propX
            value: valueX

    - name: a-json-returned-as-envoy-metadata
      wrapper: envoyDynamicMetadata
      wrapperKey: auth-data
      json:
        properties:
          - name: api-key-ns
            valueFrom:
              authJSON: auth.identity.metadata.namespace
          - name: api-key-name
            valueFrom:
              authJSON: auth.identity.metadata.name
```

### Festival Wristband tokens ([`response.wristband`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Response_Wristband))

Festival Wristbands are signed OpenID Connect JSON Web Tokens (JWTs) issued by Authorino at the end of the auth pipeline and passed back to the client, typically in added HTTP response header. It is an opt-in feature that can be used to implement Edge Authentication Architecture (EAA) and enable token normalization. Authorino wristbands include minimal standard JWT claims such as `iss`, `iat`, and `exp`, and optional user-defined custom claims, whose values can be static or dynamically fetched from the authorization JSON.

The Authorino `AuthConfig` custom resource below sets an API protection that issues a wristband after a successful authentication via API key. Apart from standard JWT claims, the wristband contains 2 custom claims: a static value `aud=internal` and a dynamic value `born` that fetches from the authorization JSON the date/time of creation of the secret that represents the API key used to authenticate.

```yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  namespace: my-namespace
  name: my-api-protection
spec:
  hosts:
    - my-api.io
  identity:
    - name: edge
      apiKey:
        labelSelectors:
          authorino.3scale.net/managed-by: authorino
      credentials:
        in: authorization_header
        keySelector: APIKEY
  response:
    - name: my-wristband
      wristband:
        issuer: https://authorino-oidc.authorino.svc:8083/my-namespace/my-api-protection/my-wristband
        customClaims:
          - name: aud
            value: internal
          - name: born
            valueFrom:
              authJSON: auth.identity.metadata.creationTimestamp
        tokenDuration: 300
        signingKeyRefs:
          - name: my-signing-key
            algorithm: ES256
          - name: my-old-signing-key
            algorithm: RS256
      wrapper: httpHeader # can be omitted
      wrapperKey: x-ext-auth-wristband # whatever http header name desired - defaults to the name of  the response config ("my-wristband")
```

The signing key names listed in `signingKeyRefs` must match the names of Kubernetes `Secret` resources created in the same namespace, where each secret contains a `key.pem` entry that holds the value of the private key that will be used to sign the wristbands issued, formatted as [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail). The first key in this list will be used to sign the wristbands, while the others are kept to support key rotation.

For each protected API configured for the Festival Wristband issuing, Authorino exposes the following OpenID Connect Discovery well-known endpoints (available for requests within the cluster):
- **OpenID Connect configuration:**<br/>
  https://authorino-oidc.authorino.svc:8083/{namespace}/{api-protection-name}/{response-config-name}/.well-known/openid-configuration
- **JSON Web Key Set (JWKS) well-known endpoint:**<br/>
  https://authorino-oidc.authorino.svc:8083/{namespace}/{api-protection-name}/{response-config-name}/.well-known/openid-connect/certs

### _Extra:_ Response wrappers ([`wrapper`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Response_Wrapper) and [`wrapperKey`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#Response_Wrapper))

#### Added HTTP headers

By default, Authorino dynamic responses (injected JSON and Festival Wristband tokens) are passed back to Envoy, stringified, as injected HTTP headers. This can be made explicit by setting the `wrapper` property of the response config to `httpHeader`.

The property `wrapperKey` controls the name of the HTTP header, with default to the name of dynamic response config when omitted.

#### Envoy Dynamic Metadata

Authorino dynamic responses (injected JSON and Festival Wristband tokens) can be passed back to Envoy in the form of Envoy Dynamic Metadata. To do so, set the `wrapper` property of the response config to `envoyDynamicMetadata`.

A response config with `wrapper=envoyDynamicMetadata` and `wrapperKey=auth-data` in the `AuthConfig` can be configured in the Envoy route or virtual host setting to be passed to rate limiting filter as below. The metadata content is expected to be a dynamic JSON injected by Authorino containing `{ "auth-data": { "api-key-ns": string, "api-key-name": string } }`. (See the response config `a-json-returned-as-envoy-metadata` in the example for the [JSON injection feature](#json-injection-responsejson) above)

```yaml
# Envoy config snippet to inject `user_namespace` and `username` rate limit descriptors from metadata returned by Authorino
rate_limits:
- actions:
    - metadata:
        metadata_key:
          key: "envoy.filters.http.ext_authz"
          path:
          - key: auth-data
          - key: api-key-ns
        descriptor_key: user_namespace
    - metadata:
        metadata_key:
          key: "envoy.filters.http.ext_authz"
          path:
          - key: auth-data
          - key: api-key-name
        descriptor_key: username
```

### _Extra:_ Custom denial status ([`denyWith`](https://pkg.go.dev/github.com/kuadrant/authorino/api/v1beta1?utm_source=gopls#DenyWith))

By default, Authorino will inform Envoy to respond with `401 Unauthorized` or `403 Forbidden` respectively when the identity verification (phase i of the [Auth Pipeline](./architecture.md#the-auth-pipeline)) or authorization (phase ii) fail. These can be customized by specifying `spec.denyWith` in the `AuthConfig`.

## Common feature: Priorities

_Priorities_ allow to set sequence of execution for blocks of concurrent evaluators within phases of the [Auth Pipeline](./architecture.md#the-auth-pipeline-aka-enforcing-protection-in-request-time).

Evaluators of same priority execute concurrently to each other "in a block". After syncing that block (i.e. after all evaluators of the block have returned), the next block of evaluator configs of consecutive priority is triggered.

Use cases for priorities are:
1. Saving expensive tasks to be triggered when there's a high chance of returning immediately after finishing executing a less expensive one – e.g.
    - an identity config that calls an external IdP to verify a token that is rarely used, compared to verifying JWTs preferred by most users of the service;
    - an authorization policy that performs some quick checks first, such as verifying allowed paths, and only if it passes, moves to the evaluation of a more expensive policy.
2. Establishing dependencies between evaluators - e.g.
    - an external metadata request that needs to wait until a previous metadata responds first (in order to use data from the response)

Priorities can be set using the `priority` property available in all evaluator configs of all phases of the Auth Pipeline (identity, metadata, authorization and response). The lower the number, the highest the priority. By default, all evaluators have priority 0 (i.e. highest priority).

Consider the following example to understand how priorities work:

```yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
    - talker-api
  identity:
    - name: tier-1
      priority: 0
      apiKey:
        labelSelectors:
          tier: "1"
    - name: tier-2
      priority: 1
      apiKey:
        labelSelectors:
          tier: "2"
    - name: tier-3
      priority: 1
      apiKey:
        labelSelectors:
          tier: "3"
  metadata:
    - name: first
      http:
        endpoint: http://talker-api:3000
        method: GET
    - name: second
      priority: 1
      http:
        endpoint: http://talker-api:3000/first_uuid={auth.metadata.first.uuid}
        method: GET
  authorization:
    - name: allowed-endpoints
      json:
        conditions:
          - selector: context.request.http.path
            operator: neq
            value: /hi
          - selector: context.request.http.path
            operator: neq
            value: /hello
          - selector: context.request.http.path
            operator: neq
            value: /aloha
          - selector: context.request.http.path
            operator: neq
            value: /ciao
        rules:
          - selector: deny
            operator: eq
            value: "true"
    - name: more-expensive-policy # no point in evaluating this one if it's not an allowed endpoint
      priority: 1
      opa:
        inlineRego: |
          allow { true }
  response:
    - name: x-auth-data
      json:
        properties:
          - name: tier
            valueFrom:
              authJSON: auth.identity.metadata.labels.tier
          - name: first-uuid
            valueFrom:
              authJSON: auth.metadata.first.uuid
          - name: second-uuid
            valueFrom:
              authJSON: auth.metadata.second.uuid
          - name: second-path
            valueFrom:
              authJSON: auth.metadata.second.path
```

For the `AuthConfig` above,

- Identity configs `tier-2` and `tier-3` (priority 1) will only trigger (concurrently) in case `tier-1` (priority 0) fails to validate the authentication token first. (This behavior happens without perjudice of context canceling between concurrent evaluators – i.e. evaluators that _are_ triggered concurrently to another, such as `tier-2` and `tier-3`, continue to cancel the context of each other if any of them succeeds validating the token first.)

- Metadata source `second` (priority 1) uses the response of the request issued by metadata source `first` (priority 0), so it will wait for `first` to finish by triggering only in the second block.

- Authorization policy `allowed-endpoints` (piority 0) is considered to be a lot less expensive than `more-expensive-policy` (priority 1) and has a high chance of denying access to the protected service (if the path is not one of the allowed endpoints). By setting different priorities to these policies we ensure the more expensive policy if triggered in sequence of the less expensive one, instead of concurrently.
