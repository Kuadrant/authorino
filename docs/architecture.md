# Authorino architecture

- [Protecting upstream APIs with Envoy and Authorino](#protecting-upstream-apis-with-envoy-and-authorino)
- [The Authorino `Service` Custom Resource Definition (CRD)](#the-authorino-service-custom-resource-definition-crd)
- [The "auth pipeline" (aka Authorino's 3 core "phases")](#the-auth-pipeline-aka-authorinos-3-core-phases)
- [List of features](#list-of-features)
  - [OAuth 2.0 (token introspetion)](#oauth-20-token-introspection)
  - [OpenID Connect (OIDC)](#openid-connect-oidc)
  - [User-Managed Access (UMA)](#user-managed-access-uma)
  - [Open Policy Agent (OPA)](#open-policy-agent-opa)

## Protecting upstream APIs with Envoy and Authorino

Typically, upstream APIs are deployed to the same Kubernetes cluster and namespace where the Envoy proxy and Authorino is running (although not necessarily). Whatever is the case, Envoy proxy must be serving the upstream API (see Envoy's [HTTP route components](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto) and virtual hosts) and pointing to Authorino in the external authorization filter.

An `Ingress` resource exposing Envoy service on a host name that must resolves to the Kubernetes cluster and identifies the API for external users. This host name is important as well for Authorino as it goes in the Authorino `Service` custom resource that declares the protection to the API.

You must then be ready to write and apply the custom resource that describes the desired state of the protection for the API.

There is no need to redeploy neither Authorino nor Envoy after applying a protection config. Authorino controller will automatically detect any changes relative to `config.authorino.3scale.net`/`Service` resources and reconcile them inside the running instances.

## The Authorino `Service` Custom Resource Definition (CRD)

Please check out the [spec](/config/crd/bases/config.authorino.3scale.net_services.yaml) of the Authorino `Service` custom resource for the details.

A list of more concrete examples can be found [here](/examples).

## The "auth pipeline" (aka Authorino's 3 core "phases")

In each request to the protected API, Authorino triggers the so-called "auth pipeline", a set of configured *evaluators* organized in up to 3 "phases" – namely (i) Identity phase, (ii) Metadata phase and (iii) Authorization phase. The evaluators in each phase are concurrent to each other, while the 3 phases are sequential.

- **(i) Identity phase:** at least one source of identity must resolve the supplied credential in the request into a valid identity or Authorino will otherwise reject the request as unauthenticated.
- **(ii) Metadata phase:** completely optional fetching of additional data from external sources, to add up to context information and identity information, and used in authorization policies (phase iii).
- **(iii) Authorization phase:** all policies must either explicitly skipped or evaluate to a positive result ("authorized"), or Authorino will otherwise reject the request as unauthorized.

Along the auth pipeline, Authorino builds the *authorization payload*, a JSON content composed of *context* information about the request, as provided by the proxy to Authorino, plus *auth* objects resolved and collected along of phases (i) and (ii). In each phase, the authorization JSON can be accessed by the evaluators, leading to phase (iii) counting with a payload (input) that looks like the following:

```jsonc
// The authorization JSON combined along Authorino's auth pipeline for each request
{
  "context": { // the input from the proxy
    "origin": {…},
    "request": {
      "http": {
        "method": "…",
        "headers": {…},
        "path": "/…",
        "host": "…",
        …
      }
    }
  },
  "auth": {
    "identity": {
      // the identity resolved, from the supplied credentials, by one of the evaluators of phase (i)
    },
    "metadata": {
      // each metadata object/collection resolved by the evaluators of phase (ii)
    }
  }
}
```

The authorization policies evaluated in phase (iii) can use any info from the authorization JSON to define rules.

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
      <td>API key</td>
      <td>Represented as Kubernetes `Secret` resources. The secret MUST contain an entry `api_key` that holds the value of the API key. The secret MUST also contain at least one lable `authorino.3scale.net/managed-by` with whatever value, plus any number of optional labels. The labels are used by Authorino to match corresponding API protections that accept the API key as valid credential.</td>
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
      <td>OAuth 2.0 (token introspection)</td>
      <td>Online introspection of access tokens with an OAuth 2.0 server.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>OpenID Connect (OIDC)</td>
      <td>Offline signature verification and time validation of OpenID Connect ID tokens (JWTs). Authorino caches the OpenID Connect configuration and JSON Web Key Set (JWKS) obtained from the OIDC Discovery well-known endpoint, and uses them to verify and validate tokens in request time.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>Kubernetes auth</td>
      <td>Online verification of Kubernetes access tokens through the Kubernetes TokenReview API. The `audiences` of the token MUST include the ones specified in the API protection state, which, when omitted, is assumed to be equal to the host name of the protected API. It can be used to authenticate Kubernetes `Service Account`s (e.g. other pods running in the cluster) and users of the cluster in general.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>OpenShift OAuth (user-echo endpoint)</td>
      <td>Online token introspection of OpenShift-valid access tokens based on OpenShift's user-echo endpoint.</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td rowspan="3">Ad-hoc authorization metadata</td>
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
      <td>HTTP GET-by-POST</td>
      <td>Generic online HTTP request to a service. It can be used to fetch online metadata for the auth pipeline or as a web hook.</td>
      <td>Planned (<a href="https://github.com/kuadrant/authorino/issues/10">#10</a>)</td>
    </tr>
    <tr>
      <td rowspan="4">Policy enforcement</td>
      <td>JSON pattern matching (e.g. JWT claims)</td>
      <td>Authorization policies represented as simple JSON pattern-matching rules. Values can be selected from the authorization JSON built along the auth pipeline. Operations include _equals_ (`eq`), _not equal_ (`neq`), _includes_ (`incl`, for arrays), _excludes_ (`excl`, for arrays) and _matches_ (`matches`, for regular expressions). Individuals policies can be optionally skipped based on "conditions" represented with similar data selectors and operators.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td>OPA Rego policies</td>
      <td>Built-in evaluator of Open Policy Agent (OPA) inline Rego policies. The policies written in Rego language are compiled and cached by Authorino in reconciliation-time, and evaluated against the authorization JSON in every request.</td>
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
      <td colspan="2">Festival wristbands</td>
      <td>JWTs issued by Authorino at the end of the auth pipeline and passed back to the client in the HTTP response header `X-Ext-Auth-Wristband`. Opt-in feature that can be used to enable Edge Authentication and token normalization, as well as to carry data from the external authorization back to the client (with support to static and dynamic custom claims). Authorino also exposes well-known endpoints for OpenID Connect Discovery, so the wristbands can be verified and validated, including by Authorino itself using the OIDC identity verification feature.</td>
      <td>Ready</td>
    </tr>
    <tr>
      <td colspan="2">Multitenancy</td>
      <td>Managed instances of Authorino offered to API providers who create and maintain their own API protection states within their own realms and namespaces.</td>
      <td>In analysis</td>
    </tr>
    <tr>
      <td colspan="2">External policy registry</td>
      <td>Fetching of compatible policies from an external registry, in reconciliation-time.</td>
      <td>In analysis</td>
    </tr>
  </tbody>
</table>

### OAuth 2.0 (token introspection)

Authorino performs OAuth 2.0 token introspection on access tokens supplied in the requests to protected APIs.

Authorino does not implement any of OAuth 2.0 grants for the applications to obtain the token. However, it can verify supplied tokens with the OAuth server, including opaque tokens, as long as the server exposes the `token_introspect` endpoint ([RFC 7662](https://tools.ietf.org/html/rfc7662)).

Developers must set the token introspection endpoint in the [CR spec](#the-authorino-service-custom-resource-definition-crd), as well as a reference to the Kubernetes secret storing the credentials of the OAuth client to be used by Authorino when requesting the introspect.

![OAuth 2.0 Token Introspect](http://www.plantuml.com/plantuml/png/NP1DJiD038NtSmehQuQgsr4R5TZ0gXLaHwHgD779g8aTF1xAZv0u3GVZ9BHH18YbttkodxzLKY-Q-ywaVQJ1Y--XP-BG2lS8AXcDkRSbN6HjMIAnWrjyp9ZK_4Xmz8lrQOI4yeHIW8CRKk4qO51GtYCPOaMG-D2gWytwhe9P_8rSLzLcDZ-VrtJ5f4XggvS17VXXw6Bm6fbcp_PmEDWTIs-pT4Y16sngccgyZY47b-W51HQJRqCNJ-k2O9FAcceQsomNsgBr8M1ATbJAoTdgyV2sZQJBHKueji5T96nAy-z5-vSAE7Y38gbNBDo8xGo-FZxXtQoGcYFVRm00)

### OpenID Connect (OIDC)

Authorino automatically discovers OIDC configurations for the registered issuers and verifies JSON Web Tokens (JWTs) supplied by the API consumers on each request.

Authorino also fetches the JSON Web Key Sets (JWKS) used to verify the JWTs, matching the `kid` stated in the JWT header (i.e., support to easy key rotation).

In general, OIDC confgurations are essentially used in the identity verification phase and possibly as well in the ad-hoc authorization metadata phase of Authorino. The decoded JWTs (and fetched user info) are passed in the authorization payload to phase (iii), i.e., authorization policy enforcement.

![OIDC](http://www.plantuml.com/plantuml/png/XO_1IWD138RlynIX9mLt7s1XfQANseDGnPx7sMmtE9EqcOpQjtUeWego7aF-__lubzcyMadHvMVYlLUV80bBc5GIWcb1v_eUDXY40qNoHiADKNtslRigDeaI2pINiBXRtLp3AkU2ke0EJkT0ESWBwj7zV3UryDNkO8inDckMLuPg6cddM0mXucWT11ycd9TjyF0X3AYM_v7TRjVtl_ckRTlFiOU2sVvU-PtpY4hZiU8U8DEElHN5cRIFD7Z3K_uCt_ONm4_ZkLiY3oN5Tm00)

### User-Managed Access (UMA)

User-Managed Access (UMA) is an OAuth-based protocol for resource owners to allow other users to access their resources. Since the UMA-compliant server is expected to know about the resources, Authorino includes a client that fetches resource data from the server and adds that as metadata of the authorization payload.

This enables the implementation of resource-level Attribute-Based Access Control (ABAC) policies. Attributes of the resource fetched in a UMA flow can be, e.g., the owner of the resource, or any business-level attributes stored in the UMA-compliant server.

A UMA-compliant server is an external authorization server (e.g., Keycloak) where the protected resources are registered. It can be as well the upstream API itself, as long as it implements the UMA protocol, with initial authentication by `client_credentials` grant to exchange for a Protected API Token (PAT).

![UMA](http://www.plantuml.com/plantuml/png/ZOx1IWCn48RlUOgX9pri7w0GxOBYGGGj5G_Y8QHJTp2PgPE9qhStmhBW9NWSvll__ziM2ser9rS-Y4z1GuOiB75IoGYc5Ptp7dOOXICb2aR2Wr5xUk_6QfCeiS1m1QldXn4AwXVg2ZRmUzrGYTBki_lp71gzH1lwWYaDzopV357uIE-EnH0I7cq3CSG9dLklrxF9PyLY_rAOMNWSzts11dIBdYhg6HIBL8rOuEAwAlbJiEcoN_pQj9VOMtVZxdQ_BFHBTpC5Xs31RP4FDQSV)

It's important to notice that Authorino does NOT manage resources in the UMA-compliant server. As shown in the flow above, Authorino's UMA client is only to fetch data about the requested resources. Authorino exchanges client credentials for a Protected API Token (PAT), then queries for resources whose URI match the path of the HTTP request (as passed to Authorino by the Envoy proxy) and fetches data of each macthing resource.

The resources data is added as metadata of the authorization payload and passed as input for the configured authorization policies. All resources returned by the UMA-compliant server in the query by URI are passed along. They are available in the PDPs (authorization payload) as `input.auth.metadata.custom-name => Array`. (See [The "auth pipeline"](#the-auth-pipeline-aka-authorinos-3-core-phases) for details.)

### Open Policy Agent (OPA)

You can model authorization policies in [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) and add them as part of the protection of your APIs. Authorino reconciliation cycle keeps track of any changes in the custom resources affecting the written policies and automatically recompiles them with built-in OPA module, and cache them for fast evaluation during request-time.

![OPA](http://www.plantuml.com/plantuml/png/ZSv1IiH048NXVPsYc7tYVY0oeuYB0IFUeEcKfh2xAdPUATxUB4GG5B9_F-yxhKWDKGkjhsfBQgboTVCyDw_2Q254my1Fajso5arGjmvQXOU1pe7PcvfpTys7cz22Jet7n_E1ZrlqeYkayU95yoVz7loPt7fTjCX_nPRyN98vX8iyuyWvvLc8-hx_rhw5hDZ9l1Vmv3cg6FX3CRFQ4jZ3lNjF9H9sURVvUBbw62zq4fkYbYy0)
