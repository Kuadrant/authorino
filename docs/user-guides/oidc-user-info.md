# User guide: OpenID Connect UserInfo

Fetch user info for OpenID Connect ID tokens in request-time for extra metadata for your policies and online verification of token validity.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - External auth metadata → [OIDC UserInfo](../features.md#oidc-userinfo-metadatauserinfo)
  - Identity verification & authentication → [JWT verification](../features.md#jwt-verification-authenticationjwt)
  - Authorization → [Pattern-matching authorization](../features.md#pattern-matching-authorization-authorizationpatternmatching)

  Apart from possibly complementing information of the JWT, fetching OpenID Connect UserInfo in request-time can be particularly useful for remote checking the state of the session, as opposed to only verifying the JWT/JWS offline. Implementation requires an OpenID Connect issuer ([`spec.identity.oidc`](#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc)) configured in the same `AuthConfig`.

  Check out as well the user guide about [OpenID Connect Discovery and authentication with JWTs](oidc-jwt-authentication.md).

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

Create an Authorino `AuthConfig` custom resource declaring the auth rules to be enforced:

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
  metadata:
    "userinfo":
      userInfo:
        identitySource: keycloak-kuadrant-realm
  authorization:
    "active-tokens-only":
      patternMatching:
        patterns:
        - selector: "auth.metadata.userinfo.email" # user email expected from the userinfo instead of the jwt
          operator: neq
          value: ""
EOF
```

## ❻ Obtain an access token with the Keycloak server

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster:

```sh
export $(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' -d 'scope=openid' | jq -r '"ACCESS_TOKEN="+.access_token,"REFRESH_TOKEN="+.refresh_token')
```

If your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

## ❼ Consume the API

With a valid access token:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api.127.0.0.1.nip.io:8000/hello
# HTTP/1.1 200 OK
```

Revoke the access token and try to consume the API again:

```sh
kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/logout -H "Content-Type: application/x-www-form-urlencoded" -d "refresh_token=$REFRESH_TOKEN" -d 'token_type_hint=requesting_party_token' -u demo:
```

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api.127.0.0.1.nip.io:8000/hello -i
# HTTP/1.1 403 Forbidden
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
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
