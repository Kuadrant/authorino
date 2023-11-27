# Authorino
**Kubernetes-native authorization service for tailor-made Zero Trust API security.**<br/>

A lightweight Envoy external authorization server fully manageable via Kubernetes Custom Resources.<br/>
JWT authentication, API key, mTLS, pattern-matching authz, OPA, K8s SA tokens, K8s RBAC, external metadata fetching, and [more](#list-of-features), with minimum to no coding at all, no rebuilding of your applications.

Authorino is not about inventing anything new. It's about making the best things about auth out there easy and simple to use. Authorino is multi-tenant, it's cloud-native and it's open source.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Unit Tests](https://github.com/Kuadrant/authorino/actions/workflows/go-test.yaml/badge.svg)](https://github.com/Kuadrant/authorino/actions/workflows/go-test.yaml)
[![End-to-end Tests](https://github.com/Kuadrant/authorino/actions/workflows/e2e-test.yaml/badge.svg)](https://github.com/Kuadrant/authorino/actions/workflows/e2e-test.yaml)
[![Smoke Tests](https://github.com/Kuadrant/authorino/actions/workflows/integration-test.yaml/badge.svg)](https://github.com/Kuadrant/authorino/actions/workflows/integration-test.yaml)

## Getting started

1. Deploy with the [Authorino Operator](https://github.com/kuadrant/authorino-operator)
2. Setup Envoy proxy and the [external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) filter
3. Apply an Authorino [`AuthConfig`](./docs/architecture.md#the-authorino-authconfig-custom-resource-definition-crd) custom resource
4. Obtain an authentication token and start sending requests

The full [Getting started](./docs/getting-started.md) page of the docs provides details for the steps above, as well as information about requirements and next steps.

Or try out our [Hello World](./docs/user-guides/hello-world.md) example.

For general information about protecting your service using Authorino, check out the [docs](./docs/README.md).

## Use-cases

The [User guides](./docs/user-guides.md) section of the docs gathers several AuthN/AuthZ use-cases as well as the instructions to implement them using Authorino. A few examples are:

- [Authentication with JWTs and OpenID Connect Discovery](./docs/user-guides/oidc-jwt-authentication.md)
- [Authentication with API keys](./docs/user-guides/api-key-authentication.md)
- [Authentication with Kubernetes SA tokens (TokenReview API)](./docs/user-guides/kubernetes-tokenreview.md)
- [Authentication with X.509 certificates and mTLS](./docs/user-guides/mtls-authentication.md)
- [Authorization with JSON pattern-matching rules (e.g. JWT claims, request attributes, etc)](./docs/user-guides/json-pattern-matching-authorization.md)
- [Authorization with Open Policy Agent (OPA) Rego policies](./docs/user-guides/opa-authorization.md)
- [Authorization using the Kubernetes RBAC (rules stated in K8s `Role` and `RoleBinding` resources)](./docs/user-guides/kubernetes-subjectaccessreview.md)
- [Authorization using auth metadata fetched from external sources](./docs/user-guides/external-metadata.md)
- [OIDC authentication and RBAC with Keycloak JWTs](./docs/user-guides/oidc-rbac.md)
- [Injecting auth data into the request (HTTP headers, Wristband tokens, rate-limit metadata, etc)](./docs/user-guides/injecting-data.md)
- [Authorino for the Kubernetes control plane (aka Authorino as ValidatingWebhook service)](./docs/user-guides/validating-webhook.md)

## How it works

Authorino enables hybrid API security, with usually no code changes required to your application, tailor-made for your own combination of authentication standards and protocols and authorization policies of choice.

Authorino implements [Envoy Proxy](https://www.envoyproxy.io)'s [external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) gRPC protocol, and is a part of Red Hat [Kuadrant](https://github.com/kuadrant) architecture.

Under the hood, Authorino is based on Kubernetes [Custom Resource Definitions](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources) and the [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator).

**Bootstrap and configuration:**

1. Deploy the service/API to be protected (_"Upstream"_), Authorino and Envoy
2. Write and apply an Authorino `AuthConfig` Custom Resource associated to the public host of the service

**Request-time:**

<picture>
  <source media="(prefers-color-scheme: light)" srcset="http://www.plantuml.com/plantuml/png/VP51IyH038NlyojoNyIx1rbTLeI2NMJreXwodRGTx4ngaX7ghtTGALMXrvVllS1xMpKKot5mc8rJZYSIj-EaEPB0sINiqpjFS06tn-C1XDuogRbliLolilKi8N4Xkll3pdN2UVoIIqWREWS02-gFvP4aj1C4Jyc2JUlm3LdJGoH3ZuRhx3wrB0q15kq3HXv24qZNFTSv31wQhCOHX7JafBHksU4mdB1vLKV9kmMsAAwkpk_g2fxJvb_sNEF3g2Q4iU1FTVNogspO07fF7df2Jw9kXiiNcAVwMMZEtbBoPTPF">
  <img alt="How it works" src="http://www.plantuml.com/plantuml/dpng/VP51IyH038NlyojoNyIx1rbTLeI2NMJreXwodRGTx4ngaX7ghtTGALMXrvVllS1xMpKKot5mc8rJZYSIj-EaEPB0sINiqpjFS06tn-C1XDuogRbliLolilKi8N4Xkll3pdN2UVoIIqWREWS02-gFvP4aj1C4Jyc2JUlm3LdJGoH3ZuRhx3wrB0q15kq3HXv24qZNFTSv31wQhCOHX7JafBHksU4mdB1vLKV9kmMsAAwkpk_g2fxJvb_sNEF3g2Q4iU1FTVNogspO07fF7df2Jw9kXiiNcAVwMMZEtbBoPTPF">
</picture>

1. A user or service account (_"Consumer"_) obtains an access token to consume resources of the _Upstream_ service, and sends a request to the _Envoy_ ingress endpoint
2. The Envoy proxy establishes fast gRPC connection with _Authorino_ carrying data of the HTTP request (context info), which causes Authorino to lookup for an `AuthConfig` Custom Resource to enforce (pre-cached)
3. **Identity verification (authentication) phase** - Authorino verifies the identity of the consumer, where at least one authentication method/identity provider must go through
4. **External metadata phase** - Authorino fetches additional metadata for the authorization from external sources (optional)
5. **Policy enforcement (authorization) phase** - Authorino takes as input a JSON composed out of context data, resolved identity object and fetched additional metadata from previous phases, and triggers the evaluation of user-defined authorization policies
6. **Response (metadata-out) phase** – Authorino builds user-defined custom responses (dynamic JSON objects and/or _Festival Wristband_ OIDC tokens), to be supplied back to the client and/or upstream service within added HTTP headers or as Envoy Dynamic Metadata (optional)
7. **Callbacks phase** – Authorino sends callbacks to specified HTTP endpoints (optional)
8. Authorino and Envoy settle the authorization protocol with either OK/NOK response
9. If authorized, Envoy triggers other HTTP filters in the chain (if any), pre-injecting eventual dynamic metadata returned by Authorino, and ultimately redirects the request to the _Upstream_
10. The _Upstream_ serves the requested resource to the consumer

<details markdown="1">
  <summary>More</summary>

  The [Architecture](./docs/architecture.md) section of the docs covers details of protecting your APIs with Envoy and Authorino, including information about topology (centralized gateway, centralized authorization service or sidecars), deployment modes (cluster-wide reconciliation vs. namespaced instances), an specification of Authorino's [`AuthConfig`](./docs/architecture.md#the-authorino-authconfig-custom-resource-definition-crd) Custom Resource Definition (CRD) and more.

  You will also find in that section information about what happens in request-time (aka Authorino's [Auth Pipeline](./docs/architecture.md#the-auth-pipeline-aka-enforcing-protection-in-request-time)) and how to leverage the [Authorization JSON](./docs/architecture.md#the-authorization-json) for writing policies, dynamic responses and other features of Authorino.
</details>

## List of features

<table>
  <thead>
    <tr>
      <th colspan="2">Feature</th>
      <th>Stage</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="9">Identity verification & authentication</td>
      <td>JOSE/JWT validation <small>(OpenID Connect)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>OAuth 2.0 Token Introspection <small>(opaque tokens)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Kubernetes TokenReview <small>(SA tokens)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>OpenShift User-echo endpoint</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td>API key authentication</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>mTLS authentication</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>HMAC authentication</td>
      <td>Planned (<a href="https://github.com/kuadrant/authorino/issues/9">#9</a>)</td>
    </tr>
    <tr>
      <td>Plain (resolved beforehand and injected in the payload)</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Anonymous access</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td rowspan="3">Ad hoc external metadata fetching</td>
      <td>OpenID Connect User Info</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>UMA-protected resource attributes</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>HTTP GET/GET-by-POST</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td rowspan="5">Policy enforcement/authorization</td>
      <td>JSON pattern matching <small>(e.g. JWT claims, request attributes checking)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>OPA/Rego policies <small>(inline and pull from registry)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Kubernetes SubjectAccessReview <small>(resource and non-resource attributes)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Authzed/SpiceDB</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Keycloak Authorization Services (UMA-compliant Authorization API)</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="4">Custom responses</td>
      <td>Festival Wristbands tokens <small>(token normalization, Edge Authentication Architecture)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>JSON injection <small>(header injection, Envoy Dynamic Metadata)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Plain text value <small>(header injection)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Custom response status code/messages <small>(e.g. redirect)</small></td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Callbacks</td>
      <td>HTTP endpoints</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td rowspan="6">Caching</td>
      <td>OpenID Connect and User-Managed Access configs</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>JSON Web Keys (JWKs) and JSON Web Key Sets (JWKS)</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Access tokens</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>External metadata</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Precompiled Rego policies</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td>Policy evaluation</td>
      <td><i>Ready</i></td>
    </tr>
    <tr>
      <td colspan="2">Sharding <small>(lookup performance, multitenancy)</small></td>
      <td><i>Ready</i></td>
    </tr>
  </tbody>
</table>

For a detailed description of the features above, refer to the [Features](./docs/features.md) page.

## FAQ

<details markdown="1">
  <summary><strong>Do I need to deploy Envoy?</strong></summary>

  Authorino is built from the ground up to work well with Envoy. It is strongly recommended that you leverage Envoy along side Authorino. That said, it is possible to use Authorino without Envoy.

  Authorino implements Envoy's [external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) gRPC protocol and therefore will accept any client request that complies.

  Authorino also provides a second interface for [raw HTTP authorization](./docs/architecture.md#raw-http-authorization-interface), suitable for using with Kubernetes ValidatingWebhook and other integrations (e.g. other proxies).

  The only attribute of the authorization request that is strictly required is the host name. (See [Host lookup](./docs/architecture.md#host-lookup) for more information.) The other attributes, such as method, path, headers, etc, might as well be required, depending on each `AuthConfig`. In the case of the gRPC [`CheckRequest`](https://pkg.go.dev/github.com/envoyproxy/go-control-plane/envoy/service/auth/v3?utm_source=gopls#CheckRequest) method, the host is supplied in `Attributes.Request.Http.Host` and alternatively in `Attributes.ContextExtensions["host"]`. For raw HTTP authorization requests, the host must be supplied in `Host` HTTP header.

  Check out [Kuadrant](https://docs.kuadrant.io/kuadrant-operator) for easy-to-use Envoy and Authorino deployment & configuration for API management use-cases, using Kubernetes Custom Resources.
</details>

<details markdown="1">
  <summary><strong>Is Authorino an Identity Provider (IdP)?</strong></summary>

  No, Authorino is not an Identity Provider (IdP). Neither it is an auth server of any kind, such as an OAuth2 server, an OpenID Connect (OIDC) server, a Single Sign On (SSO) server.

  Authorino is not an identity broker either. It can verify access tokens from multiple trusted sources of identity and protocols, but it will not negotiate authentication flows for non-authenticated access requests. Some tricks nonetheless can be done, for example, to [redirect unauthenticated users to a login page](./docs/user-guides/deny-with-redirect-to-login.md).

  For an excellent auth server that checks all the boxes above, check out [Keycloak](https://www.keycloak.org).
</details>


<details markdown="1">
  <summary><strong>How does Authorino compare to Keycloak?</strong></summary>

  Keycloak is a proper auth server and identity provider (IdP). It offers a huge set of features for managing identities, identity sources with multiple user federation options, and a platform for authentication and authorization services.

  Keycloak exposes authenticators that implement protocols such as OpenID Connect. The is a one-time flow that establishes the delegation of power to a client, for a short period of time. To be consistent with Zero Trust security, you want a validator to verify the short-lived tokens in every request that tries to reach your protected service/resource. This step that will repeat everytime could save heavy looking up into big tables of tokens and leverage cached authorization policies for fast in-memory evaluation. This is where Authorino comes in.

  Authorino verifies and validates Keycloak-issued ID tokens. OpenID Connect Discovery is used to request and cache JSON Web Key Sets (JWKS), used to verify the signature of the tokens without having to contact again with the Keycloak server, or looking in a table of credentials. Moreover, user long-lived credentials are safe, rather than spread in hops across the network.

  You can also use Keycloak for storing auth-relevant resource metadata. These can be fetched by Authorino in request-time, to be combined into your authorization policies. See Keycloak Authorization Services and User-Managed Access (UMA) support, as well as Authorino [UMA external metadata](./docs/features.md#user-managed-access-uma-resource-registry-metadatauma) counter-part.
</details>

<details markdown="1">
  <summary><strong>Why doesn't Authorino handle OAuth flows?</strong></summary>

  It has to do with trust. OAuth grants are supposed to be negotiated directly between whoever owns the long-lived credentials in one hand (user, service accounts), and the trustworthy auth server that receives those credentials – ideally with minimum number of hops in the middle – and exchanges them for short-lived access tokens, on the other end.

  There are use-cases for Authorino running in the edge (e.g. Edge Authentication Architecture and token normalization), but in most cases Authorino should be seen as a last-mile component that provides decoupled identity verification and authorization policy enforcement to protected services in request-time. In this sense, the OAuth grant is a pre-flight exchange that happens once and as direct and safe as possible, whereas auth enforcement is kept lightweight and efficient.
</details>

<details markdown="1">
  <summary><strong>Where does Authorino store users and roles?</strong></summary>

  Authorino does not store users, roles, role bindings, access control lists, or any raw authorization data. Authorino handles policies, where even these policies can be stored elsewhere (as opposed to stated inline inside of an Authorino `AuthConfig` CR).

  Authorino evaluates policies for stateless authorization requests. Any additional context is either resolved from the provided payload or static definitions inside the policies. That includes extracting user information from a JWT or client TLS certificate, requesting user metadata from opaque authentication tokens (e.g. API keys) to the trusted sources actually storing that content, obtaining synchronous HTTP metadata from services, etc.

  In the case of authentication with API keys, as well as its derivative to model HTTP Basic Auth, user data are stored in Kubernetes `Secret`s. The secret's keys, annotations and labels are usually the structures used to organize the data that later a policy evaluated in Authorino may require. Strictly, those are not Authorino data structures.
</details>

<details markdown="1">
  <summary><strong>Can't I just use Envoy JWT Authentication and RBAC filters?</strong></summary>

  Envoy's [JWT Authentication](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/jwt_authn/v3/config.proto.html) works pretty much similar to Authorino's [JOSE/JWT verification and validation for OpenID Connect](./docs/features.md#jwt-verification-authenticationjwt). In both cases, the JSON Web Key Sets (JWKS) to verify the JWTs are auto-loaded and cached to be used in request-time. Moreover, you can configure for details such as where to extract the JWT from the HTTP request (header, param or cookie) and do some cool tricks regarding how dynamic metadata based on JWT claims can be injected to consecutive filters in the chain.

  However, in terms of authorization, while Envoy's implementation essentially allows to check for the list of audiences (`aud` JWT claim), Authorino opens up for a lot more options such as pattern-matching rules with operators and conditionals, built-in OPA and other methods of evaluating authorization policies.

  Authorino also allows to combine JWT authentication with other types of authentication to support different sources of identity and groups of users such as API keys, Kubernetes tokens, OAuth opaque tokens , etc.

  In summary, Envoy's JWT Authentication and Envoy RBAC filter are excellent solutions for simple use-cases where JWTs from one single issuer is the only authentication method you are planning to support and limited to no authorization rules suffice. On the other hand, if you need to integrate more identity sources, different types of authentication, authorization policies, etc, you might to consider Authorino.
</details>

<details markdown="1">
  <summary><strong>Should I use Authorino if I already have Istio configured?</strong></summary>

  Istio is a great solution for managing service meshes. It delivers an excellent platform with an interesting layer of abstraction on top of Envoy proxy's virtual omnipresence within the mesh.

  There are lots of similarities, but also complementarity between Authorino and Istio and [Istio Authorization](https://istio.io/latest/docs/concepts/security/#authorization) in special.

  Istio provides a simple way to enable features that are, in many cases, features of Envoy, such as authorization based on JWTs, authorization based on attributes of the request, and activation of external authorization services, without having to deal with complex Envoy config files. See [Kuadrant](https://doc.kuadrant.io/kuadrant-operator) for a similar approach, nonetheless leveraging features of Istio as well.

  Authorino is an Envoy-compatible external authorization service. One can use Authorino with or without Istio.

  In particular, [Istio Authorization Policies](https://istio.io/latest/docs/reference/config/security/authorization-policy/) can be seen, in terms of functionality and expressiveness, as a subset of one type of authorization policies supported by Authorino, the [pattern-matching authorization](./docs/features.md#pattern-matching-authorization-authorizationpatternmatching) policies. While Istio, however, is heavily focused on specific use cases of API Management, offering a relatively limited list of [supported attribute conditions](https://istio.io/latest/docs/reference/config/security/conditions/), Authorino is more generic, allowing to express authorization rules for a wider spectrum of use cases – ACLs, RBAC, ABAC, etc, pretty much counting on any attribute of the Envoy payload, identity object and external metadata available.

  Authorino also provides built-in OPA authorization, several other methods of authentication and identity verification (e.g. Kubernetes token validation, API key-based authentication, OAuth token introspection, OIDC-discoverable JWT verification, etc), and features like fetching of external metadata (HTTP services, OIDC userinfo, UMA resource data), token normalization, wristband tokens and dynamic responses. These all can be used independently or combined, in a simple and straightforward Kubernetes-native fashion.

  In summary, one might value Authorino when looking for a policy enforcer that offers:

  1. multiple supported methods and protocols for rather hybrid authentication, encompassing future and legacy auth needs;
  2. broader expressiveness and more functionalities for the authorization rules;
  3. authentication and authorization in one single declarative manifest;
  4. capability to fetch auth metadata from external sources on-the-fly;
  5. built-in OPA module;
  6. easy token normalization and/or aiming for Edge Authentication Architecture (EAA).

  The good news is that, if you have Istio configured, then you have Envoy and the whole platform for wiring Authorino up if you want to. 😉
</details>

<details markdown="1">
  <summary><strong>Do I have to learn OPA/Rego language to use Authorino?</strong></summary>

  No, you do not. However, if you are comfortable with [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) from Open Policy Agent (OPA), there are some quite interesting things you can do in Authorino, just as you would in any OPA server or OPA plugin, but leveraging Authorino's [built-in OPA module](./docs/features.md#open-policy-agent-opa-rego-policies-authorizationopa) instead. Authorino's OPA module is compiled as part of Authorino's code directly from the Golang packages, and imposes no extra latency to the evaluation of your authorization policies. Even the policies themselves are pre-compiled in reconciliation-time, for fast evaluation afterwards, in request-time.

  On the other hand, if you do not want to learn Rego or in any case would like to combine it with declarative and Kubernetes-native authN/authZ spec for your services, Authorino does complement OPA with at least two other methods for expressing authorization policies – i.e. [pattern-matching authorization](./docs/features.md#pattern-matching-authorization-authorizationpatternmatching) and [Kubernetes SubjectAccessReview](./docs/features.md#kubernetes-subjectaccessreview-authorizationkubernetessubjectaccessreview), the latter allowing to rely completely on the Kubernetes RBAC.

  You break down, mix and combine these methods and technolgies in as many authorization policies as you want, potentially applying them according to specific conditions. Authorino will trigger the evaluation of concurrent policies in parallel, aborting the context if any of the processes denies access.

  Authorino also packages well-established industry standards and protocols for identity verification (JOSE/JWT validation, OAuth token introspection, Kubernetes TokenReview) and ad-hoc request-time metadata fetching (OIDC userinfo, User-Managed Access (UMA)), and corresponding layers of caching, without which such functionalities would have to be implemented by code.
</details>

<details markdown="1">
  <summary><strong>Can I use Authorino to protect non-REST APIs?</strong></summary>

  Yes, you can. In principle, the API format (REST, gRPC, GraphQL, etc) should not matter for the authN/authZ enforcer. There are a couple points to consider though.

  While REST APIs are designed in a way that, in most cases, information usually needed for the evaluation of authorization policies are available in the metadata of the HTTP request (method, path, headers), other API formats quite often will require processing of the HTTP body. By default, Envoy's external authorization HTTP filter will not forward the body of the request to Authorino; to change that, enable the `with_request_body` option in the Envoy configuration for the external authorization filter. E.g.:

  ```yaml
  with_request_body:
    max_request_bytes: 1024
    allow_partial_message: true
    pack_as_bytes: true
  ```

  Additionally, when enabling the request body passed in the payload to Authorino, parsing of the content should be of concern as well. Authorino provides easy access to attributes of the HTTP request, parsed as part of the [Authorization JSON](./docs/architecture.md#the-authorization-json), however the body of the request is passed as string and should be parsed by the user according to each case.

  Check out Authorino [OPA authorization](./docs/features.md#open-policy-agent-opa-rego-policies-authorizationopa) and the Rego [Encoding](https://www.openpolicyagent.org/docs/latest/policy-reference/#encoding) functions for options to parse serialized JSON, YAML and URL-encoded params. For XML transformation, an external parsing service connected via Authorino's [HTTP GET/GET-by-POST external metadata](./docs/features.md#http-getget-by-post-metadatahttp) might be required.
</details>

<details markdown="1">
  <summary><strong>Can I run Authorino other than on Kubernetes?</strong></summary>

  As of today, no, you cannot, or at least it wouldn't suit production requirements.
</details>

<details markdown="1">
  <summary><strong>Do I have to be admin of the cluster to install Authorino?</strong></summary>

  To install the Authorino Custom Resource Definition (CRD) and to define cluster roles required by the Authorino service, admin privilege to the Kubernetes cluster is required. This step happens only once per cluster and is usually equivalent to installing the [Authorino Operator](https://docs.kuadrant.io/authorino-operator).

  Thereafter, deploying instances of the Authorino service and applying `AuthConfig` custom resources to a namespace depend on the permissions set by the cluster administrator – either directly by editing the bindings in the cluster's RBAC, or via options of the operator. In most cases, developers will be granted permissions to create and manage `AuthConfig`s, and sometimes to deploy their own instances of Authorino.
</details>

<details markdown="1">
  <summary><strong>Is it OK to store AuthN/AuthZ configs as Kubernetes objects?</strong></summary>

  Authorino's API checks all the bullets to be [aggregated to the Kubernetes cluster APIs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/#should-i-add-a-custom-resource-to-my-kubernetes-cluster), and therefore using Custom Resource Definition (CRD) and the [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator) has always been an easy design decision.

  By merging the definitions of service authN/authZ to the control plane, Authorino `AuthConfig` resources can be thought as extensions of the specs of the desired state of services regarding the data flow security. The Authorino custom controllers, built-in into the authorization service, are the agents that read from that desired state and reconcile the processes operating in the data plane.

  Authorino is declarative and seamless for developers and cluster administrators managing the state of security of the applications running in the server, used to tools such as `kubectl`, the Kubernetes UI and its dashboards. Instead of learning about yet another configuration API format, Authorino users can jump straight to applying and editing YAML or JSON structures they already know, in a way that things such as `spec`, `status`, `namespace` and `labels` have the meaning they are expected to have, and docs are as close as `kubectl explain`. Moreover, Authorino does not pile up any other redundant layers of APIs, event-processing, RBAC, transformation and validation webhooks, etc. It is Kubernetes in its best.

  In terms of scale, Authorino `AuthConfig`s should grow proportionally to the number of protected services, virtually limited by nothing but the Kubernetes API data storage, while [namespace division](./docs/architecture.md#cluster-wide-vs-namespaced-instances) and [label selectors](./docs/architecture.md#sharding) help adjust horizontally and keep distributed.

  In other words, there are lots of benefits of using Kubernetes custom resources and custom controllers, and unless you are planning on bursting your server with more services than it can keep record, it is totally 👍 to store your AuthN/AuthZ configs as cluster API objects.
</details>

<details markdown="1">
  <summary><strong>Can I use Authorino for rate limiting?</strong></summary>

  You can, but you shouldn't. Check out instead [Limitador](https://github.com/kuadrant/limitador), for simple and efficient global rate limiting. Combine it with Authorino and Authorino's support for [Envoy Dynamic Metadata](./docs/features.md#envoy-dynamic-metadata) for authenticated rate limiting.
</details>

## Benchmarks

**Configuration of the tests (Authorino features):**

| Performance test           | Identity  | Metadata      | Authorization                                          | Response |
|----------------------------|:---------:|:-------------:|:------------------------------------------------------:|:--------:|
| `ReconcileAuthConfig`      | OIDC/JWT  | UserInfo, UMA | OPA<br/><sup>(inline Rego)</sup>                       | -        |
| `AuthPipeline`             | OIDC/JWT  | -             | JSON pattern-matching<br/><sup>(JWT claim check)</sup> | -        |
| `APIKeyAuthn`              | API key   | N/A           | N/A                                                    | N/A      |
| `JSONPatternMatchingAuthz` | N/A       | N/A           | JSON pattern-matching                                  | N/A      |
| `OPAAuthz`                 | N/A       | N/A           | OPA<br/><sup>(inline Rego)</sup>                       | N/A      |

**Platform:** linux/amd64<br/>
**CPU:** Intel® Xeon® Platinum 8370C 2.80GHz<br/>
**Cores:** 1, 4, 10<br/>

**Results:**
```
ReconcileAuthConfig:

        │   sec/op    │     B/op     │  allocs/op  │
*         1.533m ± 2%   264.4Ki ± 0%   6.470k ± 0%
*-4       1.381m ± 6%   264.5Ki ± 0%   6.471k ± 0%
*-10      1.563m ± 5%   270.2Ki ± 0%   6.426k ± 0%
geomean   1.491m        266.4Ki        6.456k

AuthPipeline:

        │   sec/op    │     B/op     │ allocs/op  │
*         388.0µ ± 2%   80.70Ki ± 0%   894.0 ± 0%
*-4       348.4µ ± 5%   80.67Ki ± 2%   894.0 ± 3%
*-10      356.4µ ± 2%   78.97Ki ± 0%   860.0 ± 0%
geomean   363.9µ        80.11Ki        882.5

APIKeyAuthn:

        │   sec/op    │    B/op      │ allocs/op  │
*         3.246µ ± 1%   480.0 ± 0%     6.000 ± 0%
*-4       3.111µ ± 0%   480.0 ± 0%     6.000 ± 0%
*-10      3.091µ ± 1%   480.0 ± 0%     6.000 ± 0%
geomean   3.148µ        480.0          6.000

OPAAuthz vs JSONPatternMatchingAuthz:

        │   OPAAuthz   │      JSONPatternMatchingAuthz       │
        │    sec/op    │   sec/op     vs base                │
*         87.469µ ± 1%   1.797µ ± 1%  -97.95% (p=0.000 n=10)
*-4       95.954µ ± 3%   1.766µ ± 0%  -98.16% (p=0.000 n=10)
*-10      96.789µ ± 4%   1.763µ ± 0%  -98.18% (p=0.000 n=10)
geomean    93.31µ        1.775µ       -98.10%

        │   OPAAuthz    │      JSONPatternMatchingAuthz      │
        │     B/op      │    B/op     vs base                │
*         28826.00 ± 0%   64.00 ± 0%  -99.78% (p=0.000 n=10)
*-4       28844.00 ± 0%   64.00 ± 0%  -99.78% (p=0.000 n=10)
*-10      28862.00 ± 0%   64.00 ± 0%  -99.78% (p=0.000 n=10)
geomean    28.17Ki        64.00       -99.78%

        │   OPAAuthz   │      JSONPatternMatchingAuthz      │
        │  allocs/op   │ allocs/op   vs base                │
*         569.000 ± 0%   2.000 ± 0%  -99.65% (p=0.000 n=10)
*-4       569.000 ± 0%   2.000 ± 0%  -99.65% (p=0.000 n=10)
*-10      569.000 ± 0%   2.000 ± 0%  -99.65% (p=0.000 n=10)
geomean     569.0        2.000       -99.65%
```

## Contributing

If you are interested in contributing to Authorino, please refer to the [Developer's guide](./docs/contributing.md) for info about the stack and requirements, workflow, policies and Code of Conduct.

Join us on the [#kuadrant](https://kubernetes.slack.com/archives/C05J0D0V525) channel in the Kubernetes Slack workspace, for live discussions about the roadmap and more.
