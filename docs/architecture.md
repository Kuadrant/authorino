# Architecture
- [Overview](#overview)
- [Topologies](#topologies)
  - [Centralized gateway](#centralized-gateway)
  - [Centralized authorization service](#centralized-authorization-service)
  - [Sidecars](#sidecars)
- [Cluster-wide vs. Namespaced instances](#cluster-wide-vs-namespaced-instances)
- [The Authorino `AuthConfig` Custom Resource Definition (CRD)](#the-authorino-authconfig-custom-resource-definition-crd)
- [Resource reconciliation and status update](#resource-reconciliation-and-status-update)
- [The "Auth Pipeline" (_aka:_ enforcing protection in request-time)](#the-auth-pipeline-aka-enforcing-protection-in-request-time)
- [Host lookup](#host-lookup)
  - [Avoiding host name collision](#avoiding-host-name-collision)
- [The Authorization JSON](#the-authorization-json)
- [Caching](#caching)
  - [OpenID Connect and User-Managed Access configs](#openid-connect-and-user-managed-access-configs)
  - [JSON Web Keys (JWKs) and JSON Web Ket Sets (JWKS)](#json-web-keys-jwks-and-json-web-ket-sets-jwks)
  - [Revoked access tokens](#revoked-access-tokens)
  - [External metadata](#external-metadata)
  - [Compiled Rego policies](#compiled-rego-policies)
  - [Repeated requests](#repeated-requests)
- [Sharding](#sharding)
- [RBAC](#rbac)
- [Observability](#observability)

## Overview

![Architecture](./architecture.gif)

There are a few concepts to understand Authorino's architecture. The main components are: **Authorino**, **Envoy** and the **Upstream** service to be protected. Envoy proxies requests to the the configured **virtual host** upstream service, first contacting with Authorino to decide on authN/authZ.

The topology can vary from centralized proxy and centralized authorization service, to dedicated sidecars, with the nuances in between. Read more about the topologies in the [Topologies](#topologies) section below.

Authorino is deployed using the [**Authorino Operator**](https://github.com/kuadrant/authorino-operator), from an [**`Authorino`**](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) Kubernetes custom resource. Then, from another kind of custom resource, the **[`AuthConfig`](#the-authorino-authconfig-custom-resource-definition-crd)** CRs, each Authorino instance reads and adds to **cache** the exact rules of authN/authZ to enforce for each protected host ("cache reconciliation").

Everything that the AuthConfig **reconciler** can fetch in reconciliation-time is stored in the cache. This is the case of static parameters such as signing keys, authentication secrets and authorization policies from external **policy registries**.

`AuthConfig`s can refer to identity providers (IdP) and trusted **auth servers** whose access tokens will be accepted to authenticate to the protected host. **Consumers** obtain an authentication token (short-lived access token or long-lived **API key**) and send those in the requests to the protected service.

When Authorino is triggered by Envoy via the **gRPC** interface, it starts evaluating the [**Auth Pipeline**](#the-auth-pipeline-aka-enforcing-protection-in-request-time), i.e. it applies to the request the parameters to verify the identity and to enforce authorization, as found in the cache for the requested host (See [host lookup](#host-lookup) for details).

Apart from static rules, these parameters can include instructions to contact online with external identity verifiers, external sources of **metadata** and policy decision points (**PDPs**).

On every request, Authorino's "working memory" is called [**Authorization JSON**](#the-authorization-json), a data structure that holds information about the context (the HTTP request) and objects from each phase of the auth pipeline: i.e., identity verification (phase i), ad-hoc metadata fetching (phase ii), authorization policy enforcement (phase iii) and dynamic response (phase iv). The evaluators in each of these phases can both read and write from the Authorization JSON for dynamic steps and decisions of authN/authZ.

## Topologies

Typically, upstream APIs are deployed to the same Kubernetes cluster and namespace where the Envoy proxy and Authorino is running (although not necessarily). Whatever is the case, Envoy must be proxying to the upstream API (see Envoy's [HTTP route components](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto) and virtual hosts) and pointing to Authorino in the external authorization filter.

This can be achieved with different topologies:
- Envoy can be a [centralized gateway](#centralized-gateway) with one dedicated instance of Authorino, proxying to one or more upstream services
- Envoy can be deployed as a sidecar of each protected service, but still contacting from a [centralized Authorino authorization service](#centralized-authorization-service)
- Both Envoy and Authorino deployed as [sidecars](#sidecars) of the protected service, restricting all communication between them to localhost

Each topology above induces different measures for security.

### Centralized gateway

![Centralized gateway topology](http://www.plantuml.com/plantuml/png/XOynJiKm343tdCBw0rk75aQ4_XyOsBY2rPWc-eaTEGa88Gu26pkduYJyfYf2KCJav5alJzddWbfg32OVFITKZ125PNGgaQ1e9MCIZaUS299Om3oF7fuCWD9OaAT0iFjuVO73xSrktcFolNdUqeP_j65RE_-blR_1DT_BOnDfFlrHlFYfNfvbvodOApZKuaGzor9VR-qXpuNq3iUJ06tj-nFieLjZou2kfcxvxmgiF713mnTIFxdIVI_iYMsDuHC0)

Recommended in the protected services to validate the origin of the traffic. It must have been proxied by Envoy. See Authorino [JSON injection](./features.md#json-injection-responsejson) for an extra validation option using a shared secret passed in HTTP header.

### Centralized authorization service

![Centralized Authorino topology](http://www.plantuml.com/plantuml/png/XO-xIiSm58VtFCMXWrk7n5Ma7HpSV8L3Ucn3Smcv228-Y6xkFfLFOjFIyASKEftBBz-Nf8i9Gyf6ipWhwp6W0UEiarDmXY25J8nvb3EE1DuDWB4K3XyC891CQ4TDqFnzVq7_yjoK7BtYX_Jt1vxictjVSoeTPvzdOd4X5fTYSIw-FueVxkAaI0-FqESqkQ2isoxPf_M5oYOAhoWN0DPOyPETM0voQFUVeIzJ7RS2xQswjXKJ1HCL4nksB8g-8pjae_y1)

Protected service should only listen on `localhost` and all traffic can be considered safe.

### Sidecars

![Sidecars topology](http://www.plantuml.com/plantuml/png/bOyzJWCn48NxESKe1TqMdXgXfA2WumgZtM5tbFMFPcqaX3W8TFISYfE0ipAW42bAzUpt_AplRPVCbekVOTbhI6piqSSG-ycY5ynM121nl-THCCK1UQdYy1aGJVhCOPm5DvzlhxYxlzlKd9Ewe_JZ7M_3Otmwv59FHo-khvP9PHvkS5Vo54r3NFzgDmSlfq3e30YT1Q4BGQY2QCXY3zn_5_0GgplX4O0wxDhWLR0hgQjeluRfEENkxrPGQZs2LNvwpVZV8zXA68gVlm00)

Recommended [`namespaced` instances of Authorino](#cluster-wide-vs-namespaced-instances) with [fine-grained label selectors](#sharding) to avoid unnecessary caching of `AuthConfig`s.

Apart from that, protected service should only listen on `localhost` and all traffic can be considered safe.

## Cluster-wide vs. Namespaced instances

Auhorino instances can run in either **cluster-wide** or **namespaced** mode.

Namespace-scoped instances only watch resources (`AuthConfig`s and `Secret`s) created in a given namespace. This deployment mode does not require admin privileges over the Kubernetes cluster to deploy the instance of the service (given Authorino's CRDs have been installed beforehand, such as when Authorino is installed using the [Authorino Operator](https://github.com/kuadrant-authorino-operator)).

Cluster-wide deployment mode, in contraposition, deploys instances of Authorino that watch resources across the entire cluster, consolidating all resources into a multi-namespace cache of auth configs. Admin privileges over the Kubernetes cluster is required to deploy Authorino in cluster-wide mode.

Be careful to avoid superposition when combining multiple Authorino instances and instance modes in the same Kubernetes cluster. Apart from caching unnecessary auth config data in the instances depending on your routing settings, the leaders of each instance (set of replicas) may compete for updating the status of the custom resources that are reconciled. See [Resource reconciliation and status update](#resource-reconciliation-and-status-update) for more information.

If necessary, use label selectors to narrow down the space of resources watched and reconciled by each Authorino instance. Check out the [Sharding](#sharding) section below for details.

## The Authorino `AuthConfig` Custom Resource Definition (CRD)

The desired protection for a service is declaratively stated by applying an `AuthConfig` [Custom Resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources) to the Kubernetes cluster running Authorino.

An `AuthConfig` resource typically looks like the following:

```yaml
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: my-api-protection
spec:
  # List of one or more hostname[:port] entries, lookup keys to find this config in request-time
  # Authorino will try to prevent hostname collision across Kubernetes namespaces by rejecting a hostname already taken.
  hosts:
    - my-api.io # north-south traffic
    - my-api.ns.svc.cluster.local # east-west traffic

  # List of one or more trusted sources of identity:
  # - Endpoints of issuers of OpenId Connect ID tokens (JWTs)
  # - Endpoints for OAuth 2.0 token introspection
  # - Attributes for the Kubernetes `TokenReview` API
  # - Label selectors for API keys (stored in Kubernetes `Secret`s)
  # - mTLS trusted certificate issuers
  # - HMAC secrets
  identity: […]

  # List of sources of external metadata for the authorization (optional):
  # - Endpoints for HTTP GET or GET-by-POST requests
  # - OIDC UserInfo endpoints (associated with an OIDC token issuer)
  # - User-Managed Access (UMA) resource registries
  metadata: […]

  # List of authorization policies to be enforced (optional):
  # - JSON pattern-matching rules (e.g. `context.request.http.path eq '/pets'`)
  # - Open Policy Agent (OPA) inline or external Rego policies
  # - Attributes for the Kubernetes `SubjectAccessReview` API
  authorization: […]

  # List of dynamic response elements, to inject post-external authorization data into the request (optional):
  # - JSON objects
  # - Festival Wristbands (signed JWTs issued by Authorino)
  # - Envoy Dynamic Metadata
  response: […]

  # Custom HTTP status code, message and headers to replace the default `401 Unauthorized` and `403 Forbidden` (optional)
  denyWith:
    unauthenticated:
      code: 302
      message: Redirecting to login
      headers:
        - name: Location
          value: https://my-app.io/login
    unauthorized: {…}
```

Check out the [OAS](/install/crd/authorino.kuadrant.io_authconfigs.yaml) of the `AuthConfig` CRD for a formal specification of the options for `identity` verification, external `metadata` fetching, `authorization` policies, and dynamic `response`, as well as any other host protection capability implemented by Authorino.

You can also read the specification from the CLI using the [`kubectl explain`](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#explain) command. The Authorino CRD is required to have been installed in Kubernetes cluster. E.g. `kubectl explain authconfigs.spec.identity.extendedProperties`.

A complete description of supported features and corresponding configuration options within an `AuthConfig` CR can be found in the [Features](./features.md) page.

More concrete examples of `AuthConfig`s for specific use-cases can be found in the [User guides](./user-guides.md).

## Resource reconciliation and status update

The instances of the Authorino authorization service workload, following the [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator), watch events related to the `AuthConfig` custom resources, to build and reconcile an in-memory cache of configs. Whenever a replica receives traffic for authorization request, it [looks up in the cache](#host-lookup) of `AuthConfig`s and then [triggers the "Auth Pipeline"](#the-auth-pipeline-aka-enforcing-protection-in-request-time), i.e. enforces the associated auth spec onto the request.

An instance can be a single authorization service workload or a set of replicas. All replicas watch and reconcile the same set of resources that match the `AUTH_CONFIG_LABEL_SELECTOR` and `SECRET_LABEL_SELECTOR` configuration options. (See both [Cluster-wide vs. Namespaced instances](#cluster-wide-vs-namespaced-instances) and [Sharding](#sharding), for details about defining the reconciliation space of Authorino instances.)

The above means that all replicas of an Authorino instance should be able to receive traffic for authorization requests.

Among the multiple replicas of an instance, Authorino elects one replica to be leader. The leader is responsible for updating the status of reconciled `AuthConfig`s. If the leader eventually becomes unavailable, the instance will automatically elect another replica take its place as the new leader.

The status of an `AuthConfig` tells whether the resource is "ready" (i.e. cached). It also includes summary information regarding the numbers of identity configs, metadata configs, authorization configs and response configs within the spec, as well as whether [Festival Wristband](./features.md#festival-wristband-tokens-responsewristband) tokens are being issued by the Authorino instance as by spec.

Apart from watching events related to `AuthConfig` custom resources, Authorino also watches events related to Kubernetes `Secret`s, as part of Authorino's [API key authentication](./features.md#api-key-identityapikey) feature. `Secret` resources that store API keys are linked-cached to their corresponding `AuthConfig`s. Whenever the Authorino instance detects a change in the set of API key `Secret`s linked to an `AuthConfig`s, the instance reconciles the cache.

Authorino only watches events related to `Secret`s whose `metadata.labels` match the label selector `SECRET_LABEL_SELECTOR` of the Authorino instance. The default values of the label selector for Kubernetes `Secret`s representing Authorino API keys is `authorino.kuadrant.io/managed-by=authorino`.

## The "Auth Pipeline" (_aka:_ enforcing protection in request-time)

![Authorino Auth Pipeline](auth-pipeline.png)

In each request to the protected API, Authorino triggers the so-called "Auth Pipeline", a set of configured *evaluators* that are organized in a 4-phase pipeline:

- **(i) Identity phase:** at least one source of identity (i.e., one identity evaluator) must resolve the supplied credential in the request into a valid identity or Authorino will otherwise reject the request as unauthenticated (401 HTTP response status).
- **(ii) Metadata phase:** optional fetching of additional data from external sources, to add up to context and identity information, and used in authorization policies and dynamic responses (phases iii and iv).
- **(iii) Authorization phase:** all unskipped policies must evaluate to a positive result ("authorized"), or Authorino will otherwise reject the request as unauthorized (403 HTTP response code).
- **(iv) Response phase** – Authorino builds all user-defined response items (dynamic JSON objects and/or _Festival Wristband_ OIDC tokens), which are supplied back to the external authorization client within added HTTP headers or as Envoy Dynamic Metadata

Each phase is sequential to the other, from (i) to (iv), while the evaluators within each phase are triggered concurrently or as prioritized. The **Identity** phase (i) is the only one required to list at least one evaluator (i.e. one identity source or more); **Metadata**, **Authorization** and **Response** phases can have any number of evaluators (including zero, and even be omitted in this case).

## Host lookup

Authorino reads the request host from `Attributes.Http.Host` of Envoy's [`CheckRequest`](https://pkg.go.dev/github.com/envoyproxy/go-control-plane/envoy/service/auth/v3?utm_source=gopls#CheckRequest) type, and uses it as key to lookup in the [cache](#resource-reconciliation-and-status-update) of `AuthConfig`s.

Alternatively, `host` can be supplied in `Attributes.ContextExtensions`, which takes precedence before the actual host attribute of the HTTP request. This is useful to support use cases such as of **path prefix-based lookup** and **wildcard subdomains lookup**.

If more than one host name is specified in the `AuthConfig`, all of them can be used as the key, i.e. all of them can be requested in the authorization request and will be mapped to the same config.

The host can include the port number (i.e. `hostname:port`) or it can be just the name of the host. Authorino will first try finding a config in the cache that is associated to `hostname:port` as supplied in the authorization request; if the cache misses an entry for `hostname:port`, Authorino will then remove the `:port` suffix and lookup again using just `hostname` as key. This allows to change port numbers for a same host, as long as the name of the host is the same, without having to list multiple combinations of `hostname:port` to the `AuthConfig` spec.

### Avoiding host name collision

Authorino tries to prevent host name collision across namespaces by rejecting `AuthConfig`s that include at least one host name already by another `AuthConfig` in a different namespace. This is intentionally designed to avoid that, in [cluster-wide deployments](#cluster-wide-vs-namespaced-instances) of Authorino, users of one namespace can surpersed configs of another.

## The Authorization JSON

On every Auth Pipeline, Authorino builds the **Authorization JSON**, a "working-memory" data structure composed of `context` (information about the request, as supplied by the Envoy proxy to Authorino) and `auth` (objects resolved in phases (i), (ii) and (iii) of the pipeline). The evaluators of each phase can read from the Authorization JSON and implement dynamic properties and decisions based on its values.

At phase (iii), the authorization evaluators count on an Auhtorization JSON payload that looks like the following:

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
      // each metadata object/collection resolved by the evaluators of phase (ii), by name of the evaluator
    }
  }
}
```

The policies evaluated can use any data from the authorization JSON to define authorization rules.

After phase (iii), Authorino appends to the authorization JSON the results of this phase as well, and the payload available for phase (iv) becomes:

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
      // each metadata object/collection resolved by the evaluators of phase (ii), by name of the evaluator
    },
    "authorization": {
      // each authorization policy result resolved by the evaluators of phase (iii), by name of the evaluator
    }
  }
}
```

[Festival Wristbands](#festival-wristbands) and [Dynamic JSON](#dynamic-json-response) responses can include dynamic values (custom claims/properties) fetched from the authorization JSON. These can be returned to the external authorization client in added HTTP headers or as Envoy [Well Known Dynamic Metadata](https://www.envoyproxy.io/docs/envoy/latest/configuration/advanced/well_known_dynamic_metadata). Check out [Dynamic response features](./features.md#dynamic-response-features-response) for details.

For information about reading and fetching data from the Authorization JSON (syntax, functions, etc), check out [JSON paths](./features.md#common-feature-json-paths-valuefromauthjson).

## Caching

### OpenID Connect and User-Managed Access configs

OpenID Connect and User-Managed Access configurations discovered in reconciliation-time.

### JSON Web Keys (JWKs) and JSON Web Ket Sets (JWKS)

JSON signature verification certificates discovered usually in reconciliation-time, following an OIDC discovery associated to an identity source.

### Revoked access tokens

<table>
  <tr>
    <td><small>Not implemented - In analysis (<a href="https://github.com/kuadrant/authorino/issues/19">#19</a>)</small></td>
  </tr>
</table>

Caching of access tokens identified and or notified as revoked prior to expiration.

### External metadata

<table>
  <tr>
    <td><small>Not implemented - Planned (<a href="https://github.com/kuadrant/authorino/issues/21">#21</a>)</small></td>
  </tr>
</table>

Caching of resource data obtained in previous requests.

### Compiled Rego policies

Performed automatically by Authorino in reconciliation-time for the authorization policies based on the built-in OPA module.

### Repeated requests

<table>
  <tr>
    <td><small>Not implemented - In analysis (<a href="https://github.com/kuadrant/authorino/issues/20">#20</a>)</small></td>
  </tr>
</table>

For consecutive requests performed, within a given period of time, by a same user that request for a same resource, such that the result of the auth pipeline can be proven that would not change.

## Sharding

By default, Authorino instances will watch `AuthConfig` CRs in the entire space (namespace or entire cluster; see [Cluster-wide vs. Namespaced instances](#cluster-wide-vs-namespaced-instances) for details). To support combining multiple Authorino instances and instance modes in the same Kubernetes cluster, and yet avoiding superposition between the instances (i.e. multiple instances reconciling the same `AuthConfig`s), Authorino offers support for data sharding, i.e. to horizontally narrow down the space of reconciliation of an Authorino instance to a subset of that space.

The benefits of limiting the space of reconciliation of an Authorino instance include avoiding unnecessary caching and workload in instances that do not receive corresponding traffic (according to your routing settings) and preventing leaders of multiple instances (sets of replicas) to compete on resource status updates (see [Resource reconciliation and status update](#resource-reconciliation-and-status-update) for details).

Use-cases for sharding of `AuthConfig`s:
- Horizontal load balancing of traffic of authorization requests
- Supporting for managed centralized instances of Authorino to API owners who create and maintain their own `AuthConfig`s within their own user namespaces.

Authorino's custom controllers filter the `AuthConfig`-related events to be reconciled using [Kubernetes label selectors](https://pkg.go.dev/k8s.io/apimachinery/pkg/labels#Parse), defined for the Authorino instance via `AUTH_CONFIG_LABEL_SELECTOR` environment variable. By default, `AUTH_CONFIG_LABEL_SELECTOR` is empty, meaning all `AuthConfig`s in the space are watched; this variable can be set to any value parseable as a valid label selector, causing Authorino to then watch only events of `AuthConfig`s whose `metadata.labels` match the selector.

The following are all valid examples of `AuthConfig` label selector filters:

```
AUTH_CONFIG_LABEL_SELECTOR="authorino.kuadrant.io/managed-by=authorino"
AUTH_CONFIG_LABEL_SELECTOR="authorino.kuadrant.io/managed-by=authorino,other-label=other-value"
AUTH_CONFIG_LABEL_SELECTOR="authorino.kuadrant.io/managed-by in (authorino,kuadrant)"
AUTH_CONFIG_LABEL_SELECTOR="authorino.kuadrant.io/managed-by!=authorino-v0.4"
AUTH_CONFIG_LABEL_SELECTOR="!disabled"
```

## RBAC

The table below describes the roles and role bindings defined by the Authorino service:

|                 Role               |     Kind      | Scope(*) |             Description                 |                                                    Permissions                                   |
| ---------------------------------- | ------------- |:--------:| --------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `authorino-manager-role`           | `ClusterRole` | C/N      | Role of the Authorino manager service   | Watch and reconcile `AuthConfig`s and `Secret`s                                                  |
| `authorino-manager-k8s-auth-role`  | `ClusterRole` | C/N      | Role for the Kubernetes auth features   | Create `TokenReview`s and `SubjectAccessReview`s (Kubernetes auth)                               |
| `authorino-leader-election-role`   | `Role`        | N        | Leader election role                    | Create/update the `ConfigMap` used to coordinate which replica of Authorino is the leader        |
| `authorino-authconfig-editor-role` | `ClusterRole` | -        | `AuthConfig` editor                     | R/W `AuthConfig`s; Read `AuthConfig/status`                                                      |
| `authorino-authconfig-viewer-role` | `ClusterRole` | -        | `AuthConfig` viewer                     | Read `AuthConfig`s and `AuthConfig/status`                                                       |
| `authorino-proxy-role`             | `ClusterRole` | C/N      | Kube-rbac-proxy-role (sidecar)'s role   | Create `TokenReview`s and `SubjectAccessReview`s to check permissions to the `/metrics` endpoint |
| `authorino-metrics-reader`         | `ClusterRole` | -        | Metrics reader                          | `GET /metrics`                                                                                   |

<small>(*) C - Cluster-wide | N - Authorino namespace | C/N - Cluster-wide or Authorino namespace (depending on the <a href="#cluster-wide-vs-namespaced-instances">deployment mode</a>).</small>

## Observability

Please refer to the respective user guides for info about [Metrics & Observability](./user-guides/metrics.md) and [Logging & Tracing](./user-guides/logging.md).
