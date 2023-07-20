# Host override via context extension

By default, Authorino uses the host information of the HTTP request ([`Attributes.Http.Host`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/attribute_context.proto#service-auth-v3-attributecontext-httprequest)) to lookup for an indexed AuthConfig to be enforced. The host info be overridden by supplying a `host` entry as a (per-route) context extension ([`Attributes.ContextExtensions`](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/attribute_context.proto#envoy-v3-api-field-service-auth-v3-attributecontext-context-extensions)), which takes precedence whenever present.

Overriding the host attribute of the HTTP request can be useful to support use cases such as of **path prefix-based lookup** and **wildcard subdomains lookup**.

- [Example of host override for path prefix-based lookup](#example-of-host-override-for-path-prefix-based-lookup)
- [Example of host override for wildcard subdomain lookup](#example-of-host-override-for-wildcard-subdomain-lookup)

For further details about Authorino lookup of AuthConfig, check out [Host lookup](./../architecture.md#host-lookup).

## Example of host override for path prefix-based lookup

In this use case, 2 different APIs (i.e. **Dogs API** and **Cats API**) are served under the same base domain, and differentiated by the path prefix:
- `pets.com/dogs` →  Dogs API
- `pets.com/cats` →  Cats API

Edit the Envoy config to extend the external authorization settings at the level of the routes, with the `host` value that will be favored by Authorino before the actual host attribute of the HTTP request:

```yaml
virtual_hosts:
- name: pets-api
  domains: ['pets.com']
  routes:
  - match:
      prefix: /dogs
    route:
      cluster: dogs-api
    typed_per_filter_config:
      envoy.filters.http.ext_authz:
        \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
        check_settings:
          context_extensions:
            host: dogs.pets.com
  - match:
      prefix: /cats
    route:
      cluster: cats-api
    typed_per_filter_config:
      envoy.filters.http.ext_authz:
        \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
        check_settings:
          context_extensions:
            host: cats.pets.com
```

Create the AuthConfig for the **Pets API**:

```yaml
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: dogs-api-protection
spec:
  hosts:
  - dogs.pets.com

  identity: [...]
```

Create the AuthConfig for the **Cats API**:

```yaml
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: cats-api-protection
spec:
  hosts:
  - cats.pets.com

  identity: [...]
```

Notice that the host subdomains `dogs.pets.com` and `cats.pets.com` are not really requested by the API consumers. Rather, users send requests to `pets.com/dogs` and `pets.com/cats`. When routing those requests, Envoy makes sure to inject the corresponding context extensions that will induce the right lookup in Authorino.

## Example of host override for wildcard subdomain lookup

In this use case, a single **Pets API** serves requests for any subdomain that matches `*.pets.com`, e.g.:
- `dogs.pets.com` →  Pets API
- `cats.pets.com` →  Pets API

Edit the Envoy config to extend the external authorization settings at the level of the virtual host, with the `host` value that will be favored by Authorino before the actual host attribute of the HTTP request:

```yaml
virtual_hosts:
- name: pets-api
  domains: ['*.pets.com']
  typed_per_filter_config:
    envoy.filters.http.ext_authz:
      \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
      check_settings:
        context_extensions:
          host: pets.com
  routes:
  - match:
      prefix: /
    route:
      cluster: pets-api
```

The `host` context extension used above is any key that matches one of the hosts listed in the targeted AuthConfig.

Create the AuthConfig for the **Pets API**:

```yaml
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: pets-api-protection
spec:
  hosts:
  - pets.com

  identity: [...]
```

Notice that requests to `dogs.pets.com` and to `cats.pets.com` are all routed by Envoy to the same API, with same external authorization configuration. in all the cases, Authorino will lookup for the indexed AuthConfig associated with `pets.com`. The same is valid for a request sent, e.g., to `birds.pets.com`.
