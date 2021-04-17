# Authorino

Cloud-native AuthN/AuthZ enforcer to protect APIs.

- **User authentication/identity verification**<br/>
  API key, OAuth2, OIDC, mTLS, HMAC, K8s-auth
- **Ad-hoc authorization metadata**<br/>
  OIDC UserInfo, UMA-protected resource data, HTTP GET-by-POST
- **Authorization policy enforcement**<br/>
  OPA/Rego policies, JSON/JWT pattern matching policies

Authorino enables hybrid API security layer, with usually no code changes required, according to your own desired combination of authentication standards and authorization policies.

Authorino implements [Envoy](https://www.envoyproxy.io) proxy's [external authorization](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) gRPC protocol and complies with Red Hat 3scale [Kuadrant](https://github.com/kuadrant) architecture.

## How it works

![How it works](http://www.plantuml.com/plantuml/png/TP31IiOm48JlUOebTr_0W_n5Vb0yMAHwZydM1flTkDa8VNiZWYs1NcU-NMRcKjI9rhIQyXafEt494XFxHJWXg5GqnbLbgkaTnTXXV0JFL6f2iN1p1rVwvWrkuM6QHX3ygbZK_8dD7QekB96u4HyluxtPXSvzGudp1Z4WQTJj71n2W8JgWbDtJbrfPl48cTVe8vOZUKZz_BHdjQ-vg61Re9MqVQNE_NtIZV5_K7BJq5oGGbls1m00)

1. An application client (_API consumer_) obtains credentials to consume resources of the _Upstream API_, and sends a request to the _Envoy_ exposed endpoint
2. The Envoy proxy establishes fast gRPC connection with _Authorino_ carrying data of the HTTP request (context info)
3. **Identity verification phase** - Authorino verifies the identity of the the consumer, where at least one authentication method/identity provider must answer
4. **Ad-hoc authorization metadata phase** - Authorino integrates external sources of additional metadata
5. **Policy enforcement phase** - Authorino takes as input a JSON composed of context information, resolved identity and fetched additional metadata from previous phases, and triggers the evaluation of configured authorization policies
6. Authorino and Envoy settle the authorization protocol with either a `200 OK`, `403 Forbidden` or `404 Not found` response (plus some extra details available in the `x-ext-auth-reason` header if NOK)
7. If authorized, Envoy redirects to the requested _Upstream API_
8. The _Upstream API_ serves the requested resource to the consumer

The 3 _core phases_ of Authorino [auth pipeline](docs/architecture.md#the-auth-pipeline-aka-authorinos-3-core-phases) (depicted in the diagram as steps 3, 4 and 5) rely on well-established industry standards and protocols, such as [OpenID Connect (OIDC)](https://openid.net/connect/), [User-Managed Access (UMA)](https://docs.kantarainitiative.org/uma/rec-uma-core.html), [Open Policy Agent (OPA)](https://www.openpolicyagent.org/), [mutual Transport Layer Security (mTLS)](https://www.rfc-editor.org/rfc/rfc8705.html), among others, to enable API security while allowing API developers to pick and combine protocols and settings into one hybrid cloud-native configuration.

## Architecture

The [architecture](docs/architecture.md) section of the docs covers the details of [protecting your APIs](docs/architecture.md#protecting-upstream-apis-with-envoy-and-authorino) with Envoy and Authorino, including a description of the components involved and of the [Authorino `Service` Custom Resource Definition (CRD)](docs/architecture.md#the-authorino-service-custom-resource-definition-crd). You will also find information about Authorino's [auth pipeline](docs/architecture.md#the-auth-pipeline-aka-authorinos-3-core-phases) and detailed [list of features](docs/architecture.md#list-of-features).

## Usage

1. [Deploy](docs/deploy.md) Authorino to the Kubernetes server
2. Have your upstream API [ready](docs/architecture.md#protecting-upstream-apis-with-envoy-and-authorino) to be protected
3. [Write](docs/architecture.md#the-authorino-service-custom-resource-definition-crd) and apply a `config.authorino.3scale.net`/`Service` custom resource declaring the desired state of the protection of your API

## Examples and Tutorials

The [Examples](examples) page lists several use cases and demonstrates how to implement those as Authorino custom resources. Each example use case presents a feature of Authorino and is independent from the other.

The Authorino [Tutorials](docs/tutorials.md) provide guided examples for deploying and protecting an API with Authorino and the Envoy proxy, where each tutorial combines multiple features of Authorino into one cohesive use case, resembling real life use cases.

## Terminology

You can find definitions for terms used in this document and others in the [Terminology](docs/terminology.md) document.

## Contributing

If you are interested in contributing to Authorino, please refer to instructions available [here](docs/contributing.md). You may as weel check our [Code of Conduct](docs/code_of_conduct.md).
