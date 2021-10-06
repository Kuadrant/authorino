# Authorino

Cloud-native AuthN/AuthZ enforcer for Zero Trust API protection.

- **User identity verification and authentication**<br/>
  JWTs, OIDC, OAuth2, K8s TokenReview, API key, mTLS, HMAC
- **Ad hoc authorization metadata**<br/>
  HTTP GET and GET-by-POST, OIDC UserInfo, UMA-protected resource data
- **Authorization policy enforcement**<br/>
  JSON/JWT pattern matching policies, OPA/Rego policies, K8s SubjectAccessReview
- **Token normalization / Edge Authentication**<br/>
  OIDC-compliant "Festival Wristband" ID tokens (signed JWTs)
- **Dynamic Metadata**<br/>
  Added HTTP headers and support for Envoy Dynamic Metadata

Authorino enables hybrid API security layer, with usually no code changes required, tailor-made for your combination of authentication standards and protocols and authorization policies of choice.

Authorino builds on top of the [Envoy Proxy](https://www.envoyproxy.io) [external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) gRPC protocol, and complies with Red Hat [Kuadrant](https://github.com/kuadrant) architecture.

----

## How it works

![How it works](http://www.plantuml.com/plantuml/png/VP4nImD148Nx_HMFQuFOMqYYH9I0EIJQgCLwEyajtiwSixD2_FKkfaYy8ksRzp7mlNashrRIuF9dvD6hJqZ2qlKgYM1Qo3bVJBYa3rBNBDe7TCAv9D865zTOyhViSONxpQQ5qbUXREuGrkkYM2yQMMfZzzJUkfrA6VzYj76a8J8v0CVYb7eXZTizOY2sQFlpvJkohaSYyy6RFzzTybQq8_YQ_M2K8NQHyddcfiGXe2lP944fZyAP775m9yY9bFNgyd6zmXlFfj1HKVCyPbFo2TLjKw7NzUhzdqxCu4EWW9vy8CrkWjIFc0npsEFuRKuSwig_)

1. An application client (_API consumer_) obtains credentials or access token to consume resources of the _Upstream API_, and sends a request to the _Envoy_ ingress endpoint
2. The Envoy proxy establishes fast gRPC connection with _Authorino_ carrying data of the HTTP request (context info)
3. **Identity verification phase** - Authorino verifies the identity of the the consumer, where at least one authentication method/identity provider must succeed
4. **Metadata phase** - Authorino fetches aditional metadata for the authorization from external sources (optional)
5. **Policy enforcement phase** - Authorino takes as input a JSON composed of context information, resolved identity and fetched additional metadata from previous phases, and triggers the evaluation of user-defined authorization policies
6. **Response phase** – Authorino builds user-defined custom responses (dynamic JSON objects and/or _Festival Wristband_ OIDC tokens), to be supplied back to the client and/or upstream API within added HTTP headers or as Envoy Dynamic Metadata (optional)
7. Authorino and Envoy settle the authorization protocol with either OK/NOK response (plus extra details available in the `X-Ext-Auth-Reason` and `WWW-Authenticate` headers when NOK)
8. If authorized, Envoy triggers other HTTP filters in the chain piping dynamic metadata returned by Authorino, and ultimately redirects the request to the _Upstream API_
9. The _Upstream API_ serves the requested resource to the consumer

The core phases of Authorino "[Auth Pipeline](docs/architecture.md#the-auth-pipeline)" (depicted in the diagram as steps 3 to 6) rely on well-established industry standards and protocols, such as [OpenID Connect (OIDC)](https://openid.net/connect/), [User-Managed Access (UMA)](https://docs.kantarainitiative.org/uma/rec-uma-core.html), [Open Policy Agent (OPA)](https://www.openpolicyagent.org/), [mutual Transport Layer Security (mTLS)](https://www.rfc-editor.org/rfc/rfc8705.html), plus Authorino-specific implementations for simpler use-cases, to enable Zero Trust security for APIs, while allowing developers to pick and combine protocols and settings into one cloud-native straighforward configuration (based on Kubernetes [Custom Resource Definitions](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources)).

## List of features

<table>
  <thead>
    <tr>
      <th colspan="2">Feature</th>
      <th>Description</th>
      <th>Stage</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="7">Identity verification</td>
      <td>OpenID Connect (OIDC)</td>
      <td>Offline signature verification and time validation of OpenID Connect ID tokens (JWTs). Authorino caches the OpenID Connect configuration and JSON Web Key Set (JWKS) obtained from the OIDC Discovery well-known endpoint, and uses them to verify and validate tokens in request time.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>OAuth 2.0 (token introspection)</td>
      <td>Online introspection of access tokens with an OAuth 2.0 server.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Kubernetes authN</td>
      <td>Online verification of Kubernetes access tokens through the Kubernetes TokenReview API. The <code>audiences</code> of the token MUST include the ones specified in the API protection state, which, when omitted, is assumed to be equal to the host name of the protected API. It can be used to authenticate Kubernetes <code>Service Account</code>s (e.g. other pods running in the cluster) and users of the cluster in general.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>OpenShift OAuth (user-echo endpoint)</td>
      <td>Online token introspection of OpenShift-valid access tokens based on OpenShift's user-echo endpoint.</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td>API key</td>
      <td>Represented as Kubernetes <code>Secret</code> resources. The secret MUST contain an entry <code>api_key</code> that holds the value of the API key. The secret MUST also contain at least one lable <code>authorino.3scale.net/managed-by</code> with whatever value, plus any number of optional labels. The labels are used by Authorino to match corresponding API protections that accept the API key as valid credential.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>mTLS</td>
      <td>Authentication by client certificate.</td>
      <td>Planned (<a href="https://github.com/kuadrant/authorino/issues/8">#8</a>)</td>
    </tr>
    <tr>
      <td>HMAC</td>
      <td>Authentication by Hash Message Authentication Code (HMAC), where a unique secret generated per API consumer, combined with parts of the request metadata, is used to generate a hash that is passed as authentication value by the client and verified by Authorino.</td>
      <td>Planned (<a href="https://github.com/kuadrant/authorino/issues/9">#9</a>)</td>
    </tr>
    <tr>
      <td rowspan="3">Ad hoc authorization metadata</td>
      <td>OIDC user info</td>
      <td>Online request to OpenID Connect User Info endpoint. Requires an associated OIDC identity source.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>UMA-protected resource attributes</td>
      <td>Online request to a User-Managed Access (UMA) server to fetch data from the UMA Resource Set API.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>External HTTP service</td>
      <td>Generic online HTTP request to an external service (GET or POST). It can be used to fetch online metadata for the auth pipeline or as a web hook.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td rowspan="4">Policy enforcement</td>
      <td>JSON pattern matching (e.g. JWT claims)</td>
      <td>Authorization policies represented as simple JSON pattern-matching rules. Values can be selected from the authorization JSON built along the auth pipeline. Operations include <i>equals</i> (<code>eq</code>), <i>not equal</i> (<code>neq</code>), <i>includes</i> (<code>incl</code>; for arrays), <i>excludes</i> (<code>excl</code>; for arrays) and <i>matches</i> (<code>matches</code>; for regular expressions). Individuals policies can be optionally skipped based on "conditions" represented with similar data selectors and operators.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>OPA Rego policies</td>
      <td>Built-in evaluator of Open Policy Agent (OPA) inline Rego policies. The policies written in Rego language are compiled and cached by Authorino in reconciliation-time, and evaluated against the authorization JSON in every request.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Kubernetes authZ</td>
      <td>Checks with the underlying Kubernetes cluster about whether the user can access the requested API resource, according to the authorization rules defined in the cluster's RBAC. Based on Kubernetes <code>SubjectAccessReview</code></td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Keycloak (UMA-compliant Authorization API)</td>
      <td>Online delegation of authorization to a Keycloak server.</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td>HTTP external authorization service</td>
      <td>Generic online delegation of authorization to an external HTTP service.</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="2">Custom responses</td>
      <td>Festival Wristbands</td>
      <td>Signed JWTs issued by Authorino at the end of the auth pipeline and passed back to the client (usually in an added HTTP header). Opt-in feature that can be used to implement Edge Authentication Architecture (EAA) and enable token normalization, with support to static and dynamic custom claims added to the JTW. Authorino exposes the OIDC discovery endpoints to verify and validate the wristbands, including by Authorino itself (using the OIDC identity verification feature).</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Dynamic JSON</td>
      <td>User-defined JSON objects generated from static or dynamic data of the auth pipeline, and passed back to the client either within added HTTP headers or as <a href="https://www.envoyproxy.io/docs/envoy/latest/configuration/advanced/well_known_dynamic_metadata">Envoy Dynamic Metadata</a>.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td rowspan="6">Caching</td>
      <td>OIDC and UMA configs</td>
      <td>OpenID Connect and User-Managed Access configurations discovered in reconciliation-time.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>JSON Web Keys (JWKs) and JSON Web Ket Sets (JWKS)</td>
      <td>JSON signature verification certificates discovered usually in reconciliation-time, following an OIDC discovery associated to an identity source.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Revoked access tokens</td>
      <td>Caching of access tokens identified as revoked before expiration.</td>
      <td>In analysis (<a href="https://github.com/kuadrant/authorino/issues/19">#19</a>)</td>
    </tr>
    <tr>
      <td>Resource data</td>
      <td>Caching of resource data obtained in previous requests.</td>
      <td>Planned (<a href="https://github.com/kuadrant/authorino/issues/21">#21</a>)</td>
    </tr>
    <tr>
      <td>Compiled Rego policies</td>
      <td>Performed automatically by Authorino in reconciliation-time for the authorization policies based on the built-in OPA module.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Repeated requests</td>
      <td>For consecutive requests performed, within a given period of time, by a same user that request for a same resource, such that the result of the auth pipeline can be proven that would not change.</td>
      <td>In analysis (<a href="https://github.com/kuadrant/authorino/issues/20">#20</a>)</td>
    </tr>
    <tr>
      <td colspan="2">External policy registry</td>
      <td>Fetching of compatible policies from an external registry, in reconciliation-time.</td>
      <td>Planned (<a href="https://github.com/kuadrant/authorino/issues/115">#115</a>)</td>
    </tr>
    <tr>
      <td colspan="2">Multitenancy</td>
      <td>Managed instances of Authorino offered to API providers who create and maintain their own API protection states within their own realms and namespaces.</td>
      <td>Ready</td>
    </tr>
  </tbody>
</table>

For a detailed description of the features above, refer to the [Architecture](/docs/architecture.md#feature-description) page.

## Architecture

The [Architecture](docs/architecture.md) section of the docs covers the details of [protecting your APIs](docs/architecture.md#protecting-upstream-apis-with-envoy-and-authorino) with Envoy and Authorino, including a description of the components involved and specification of the [Authorino `AuthConfig` Custom Resource Definition (CRD)](docs/architecture.md#the-authorino-authconfig-custom-resource-definition-crd).

You will also find in that section information about the Authorino [Auth Pipeline](docs/architecture.md#the-auth-pipeline), and detailed [description of features](docs/architecture.md#feature-description).

## Usage

1. [Deploy](docs/deploy.md) Authorino to the Kubernetes server
2. Have your upstream API [ready](docs/architecture.md#protecting-upstream-apis-with-envoy-and-authorino) to be protected
3. [Write](docs/architecture.md#the-authorino-authconfig-custom-resource-definition-crd) and apply a `authorino.3scale.net`/`AuthConfig` custom resource declaring the desired state of the protection of your API

## Examples and Tutorials

The [Examples](examples) page lists several use cases and demonstrates how to implement those as Authorino custom resources. Each example use case presents a feature of Authorino and is independent from the other.

The Authorino [Tutorials](docs/tutorials.md) provide guided examples for deploying and protecting an API with Authorino and the Envoy proxy, where each tutorial combines multiple features of Authorino into one cohesive use case, resembling real life use cases.

## Terminology

You can find definitions for terms used in this document and others in the [Terminology](docs/terminology.md) document.

## Contributing

If you are interested in contributing to Authorino, please refer to instructions available [here](docs/contributing.md). You may as weel check our [Code of Conduct](docs/code_of_conduct.md).
