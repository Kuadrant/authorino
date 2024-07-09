# User guide: Token normalization

Broadly, the term token normalization in authentication systems usually implies the exchange of an authentication token, as provided by the user in a given format, and/or its associated identity claims, for another freshly issued token/set of claims, of a given (normalized) structure or format.

The most typical use-case for token normalization involves accepting tokens issued by multiple trusted sources and of often varied authentication protocols, while ensuring that the eventual different data structures adopted by each of those sources are normalized, thus allowing to simplify policies and authorization checks that depend on those values. In general, however, any modification to the identity claims can be for the purpose of normalization.

This user guide focuses on the aspect of mutation of the identity claims resolved from an authentication token, to a certain data format and/or by extending them, so that required attributes can thereafter be trusted to be present among the claims, in a desired form. For such, Authorino allows to extend resolved identity objects with custom attributes (custom claims) of either static values or with values fetched from the [Authorization JSON](../architecture.md#the-authorization-json).

For not only normalizing the identity claims for purpose of writing simpler authorization checks and policies, but also getting Authorino to issue a new token in a normalized format, check the [Festival Wristband tokens](../features.md#festival-wristband-tokens-responsesuccessheadersdynamicmetadatawristband) feature.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Identity verification & authentication → [Identity extension](../features.md#extra-identity-extension-authenticationdefaults-and-authenticationoverrides)
  - Identity verification & authentication → [API key](../features.md#api-key-authenticationapikey)
  - Identity verification & authentication → [JWT verification](../features.md#jwt-verification-authenticationjwt)
  - Authorization → [Pattern-matching authorization](../features.md#pattern-matching-authorization-authorizationpatternmatching)

  Check out as well the user guides about [Authentication with API keys](api-key-authentication.md), [OpenID Connect Discovery and authentication with JWTs](oidc-jwt-authentication.md) and [Simple pattern-matching authorization policies](json-pattern-matching-authorization.md).

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)
- Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))
- [jq](https://stedolan.github.io/jq), to extract parts of JSON responses

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

Deploy the identity provider and authentication server by executing the command below. For the examples in this guide, we are going to use a Keycloak server preloaded with all required realm settings.

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

<br/>

The next steps walk you through installing Authorino, deploying and configuring a sample service called **Talker API** to be protected by the authorization service.

<table>
  <thead>
    <tr>
      <th>Using Kuadrant</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>
        <p>If you are a user of <a href="https://kuadrant.io">Kuadrant</a> and already have your workload cluster configured and sample service application deployed, as well as your Gateway API network resources applied to route traffic to your service, skip straight to step ❺.</p>
        <p>At step ❺, instead of creating an <code>AuthConfig</code> custom resource, create a Kuadrant <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> one. The schema of the AuthConfig's <code>spec</code> matches the one of the AuthPolicy's, except <code>spec.host</code>, which is not available in the Kuadrant AuthPolicy. Host names in a Kuadrant AuthPolicy are inferred automatically from the Kubernetes network object referred in <code>spec.targetRef</code> and route selectors declared in the policy.</p>
        <p>For more about using Kuadrant to enforce authorization, check out <a href="https://docs.kuadrant.io/kuadrant-operator/doc/auth">Kuadrant auth</a>.</p>
      </td>
    </tr>
  </tbody>
</table>

<br/>

## ❶ Install the Authorino Operator (cluster admin required)

The following command will install the [Authorino Operator](http://github.com/kuadrant/authorino-operator) in the Kubernetes cluster. The operator manages instances of the Authorino authorization service.

```sh
curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/utils/install.sh | bash -s
```

## ❷ Deploy Authorino

The following command will request an instance of Authorino as a separate service[^1] that watches for `AuthConfig` resources in the `default` namespace[^2], with TLS disabled[^3].

```sh
kubectl apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  listener:
    tls:
      enabled: false
  oidcServer:
    tls:
      enabled: false
EOF
```

[^1]: In contrast to a dedicated sidecar of the protected service and other architectures. Check out __Architecture > [Topologies](../architecture.md#topologies)__ for all options.
[^2]: `namespaced` reconciliation mode. See [Cluster-wide vs. Namespaced instances](../architecture.md#cluster-wide-vs-namespaced-instances).
[^3]: For other variants and deployment options, check out [Getting Started](../getting-started.md#step-request-an-authorino-instance), as well as the [`Authorino`](https://github.com/kuadrant/authorino-operator#the-authorino-custom-resource-definition-crd) CRD specification.

## ❸ Deploy the Talker API

The **Talker API** is a simple HTTP service that echoes back in the response whatever it gets in the request. We will use it in this guide as the sample service to be protected by Authorino.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## ❹ Setup Envoy

The following bundle from the Authorino examples deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up the Talker API behind the reverse-proxy, with external authorization enabled with the Authorino instance.[^4]

[^4]: For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](../getting-started.md#step-setup-envoy) page. If you are running your ingress gateway in Kubernetes and wants to avoid setting up and configuring your proxy manually, check out [Kuadrant](https://kuadrant.io).

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The command above creates an `Ingress` with host name `talker-api.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 8000 to the Envoy service running inside the cluster:

```sh
kubectl port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
```

## ❺ Create an `AuthConfig`

Create an Authorino `AuthConfig` custom resource declaring the auth rules to be enforced.

This example implements a policy that only users bound to the `admin` role can send `DELETE` requests.

The config trusts access tokens issued by a Keycloak realm as well as API keys labeled specifically to a selected group (`friends`). The roles of the identities handled by Keycloak are managed in Keycloak, as _realm roles_. Particularly, users `john` and `peter` are bound to the `member` role, while user `jane` is bound to roles `member` and `admin`. As for the users authenticating with API key, they are all bound to the `admin` role.

Without normalizing identity claims from these two different sources, the policy would have to handle the differences of data formats with additional ifs-and-elses. Instead, the config here uses the `identity.extendedProperties` option to ensure a custom `roles` (Array) claim is always present in the identity object. In the case of Keycloak ID tokens, the value is extracted from the `realm_access.roles` claim; for API key-resolved objects, the custom claim is set to the static value `["admin"]`.

<table>
  <tbody>
    <tr>
      <td>
        <b><i>Kuadrant users –</i></b>
        Remember to create an <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> instead of an AuthConfig.
        For more, see <a href="https://docs.kuadrant.io/kuadrant-operator/doc/auth">Kuadrant auth</a>.
      </td>
    </tr>
  </tbody>
</table>

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api.127.0.0.1.nip.io
  authentication:
    "keycloak-kuadrant-realm":
      jwt:
        issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
      overrides:
        "roles":
          selector: auth.identity.realm_access.roles
    "api-key-friends":
      apiKey:
        selector:
          matchLabels:
            group: friends
      credentials:
        authorizationHeader:
          prefix: APIKEY
      defaults:
        "roles":
          value: ["admin"]
  authorization:
    "only-admins-can-delete":
      when:
      - selector: context.request.http.method
        operator: eq
        value: DELETE
      patternMatching:
        patterns:
        - selector: auth.identity.roles
          operator: incl
          value: admin
EOF
```

## ❻ Create an API key

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: api-key-1
  labels:
    authorino.kuadrant.io/managed-by: authorino
    group: friends
stringData:
  api_key: ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx
type: Opaque
EOF
```

## ❼ Consume the API

### Obtain an access token and consume the API as Jane (admin)

Obtain an access token with the Keycloak server for Jane:

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for the user Jane, whose e-mail has been verified:

```sh
ACCESS_TOKEN=$(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' -d 'scope=openid' | jq -r .access_token)
```

If your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

Consume the API as Jane:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

### Obtain an access token and consume the API as John (member)

Obtain an access token with the Keycloak server for John:

```sh
ACCESS_TOKEN=$(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' -d 'scope=openid' | jq -r .access_token)
```

Consume the API as John:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 403 Forbidden
```

### Consume the API using the API key to authenticate (admin)

```sh
curl -H "Authorization: APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" -X DELETE http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 200 OK
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete secret/api-key-1
kubectl delete authconfig/talker-api-protection
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete authorino/authorino
kubectl delete namespace keycloak
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
