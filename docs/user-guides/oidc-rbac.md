# User guide: OpenID Connect (OIDC) and Role-Based Access Control (RBAC) with Authorino and Keycloak

Combine OpenID Connect (OIDC) authentication and Role-Based Access Control (RBAC) authorization rules leveraging Keycloak and Authorino working together.

In this user guide, you will learn via example how to implement a simple Role-Based Access Control (RBAC) system to protect endpoints of an API, with roles assigned to users of an Identity Provider (Keycloak) and carried within the access tokens as JSON Web Token (JWT) claims. Users authenticate with the IdP via OAuth2/OIDC flow and get their access tokens verified and validated by Authorino on every request. Moreover, Authorino reads the role bindings of the user and enforces the proper RBAC rules based upon the context.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc">OpenID Connect (OIDC) JWT/JOSE verification and validation</a></li>
      <li>Authorization → <a href="./../features.md#json-pattern-matching-authorization-rules-authorizationjson">JSON pattern-matching authorization rules</a></li>
    </ul>
  </summary>

  Check out as well the user guides about [OpenID Connect Discovery and authentication with JWTs](./oidc-jwt-authentication.md) and [Simple pattern-matching authorization policies](./json-pattern-matching-authorization.md).

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- Auth server / Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))
- [jq](https://stedolan.github.io/jq), to extract parts of JSON responses

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-trial
```

Deploy a Keycloak server preloaded with all the realm settings required for this guide:

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

Forward local requests to the instance of Keycloak running in the cluster:

```sh
kubectl -n keycloak port-forward deployment/keycloak 8080:8080 &
```

## 1. Install the Authorino Operator

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

## 2. Create the namespace

```sh
kubectl create namespace authorino
```

## 3. Deploy the Talker API

The **Talker API** is just an echo API, included in the Authorino examples. We will use it in this guide as the service to be protected with Authorino.

```sh
kubectl -n authorino apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## 4. Deploy Authorino

```sh
kubectl -n authorino apply -f -<<EOF
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

The command above will deploy Authorino as a separate service (as oposed to a sidecar of the protected API and other architectures), in `namespaced` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 5. Setup Envoy

The following bundle from the Authorino examples (manifest referred in the command below) is to apply Envoy configuration and deploy Envoy proxy, that wire up the Talker API behind the reverse-proxy and external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#1-setup-envoy) page. For a simpler and straighforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl -n authorino apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The bundle also creates an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
```

## 6. Create the `AuthConfig`

In this example, the Keycloak realm defines a few users and 2 realm roles: 'member' and 'admin'. When users authenticate to the Keycloak server by any of the supported OAuth2/OIDC flows, Keycloak adds to the access token JWT a claim `"realm_access": { "roles": array }` that holds the list of roles assigned to the user. Authorino will verify the JWT on requests to the API and read from that claim to enforce the following RBAC rules:

| Path            | Method           | Role   |
| --------------- | ---------------- |:------:|
| /resources[/*]  | GET / POST / PUT | member |
| /resources/{id} | DELETE           | admin  |
| /admin[/*]      | *                | member |

Apply the AuthConfig:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io

  identity:
  - name: keycloak-kuadrant-realm
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant

  patterns:
    member-role:
    - selector: auth.identity.realm_access.roles
      operator: incl
      value: member
    admin-role:
    - selector: auth.identity.realm_access.roles
      operator: incl
      value: admin

  authorization:
  # RBAC rule: 'member' role required for requests to /resources[/*]
  - name: rbac-resources-api
    when:
    - selector: context.request.http.path
      operator: matches
      value: ^/resources(/.*)?$
    json:
      rules:
      - patternRef: member-role

  # RBAC rule: 'admin' role required for DELETE requests to /resources/{id}
  - name: rbac-delete-resource
    when:
    - selector: context.request.http.path
      operator: matches
      value: ^/resources/\d+$
    - selector: context.request.http.method
      operator: eq
      value: DELETE
    json:
      rules:
      - patternRef: admin-role

  # RBAC rule: 'admin' role required for requests to /admin[/*]
  - name: rbac-admin-api
    when:
    - selector: context.request.http.path
      operator: matches
      value: ^/admin(/.*)?$
    json:
      rules:
      - patternRef: admin-role
EOF
```

## 7. Obtain an access token and consume the API

### Obtain an access token and consume the API as John (member)

Obtain an access token with the Keycloak server for John:

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for the user John, who is asigned to the 'member' role:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' | jq -r .access_token)
```

If otherwise your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

As John, send a `GET` request to **/resources**:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/resources -i
# HTTP/1.1 200 OK
```

As John, send a `DELETE` request to **/resources/123**:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/resources/123 -i
# HTTP/1.1 403 Forbidden
```

As John, send a `GET` request to **/admin/settings**:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/admin/settings -i
# HTTP/1.1 403 Forbidden
```

### Obtain an access token and consume the API as Jane (member/admin)

Obtain an access token from within the cluster for the user Jane, who is asigned to the 'member' and 'admin' roles:

```sh
ACCESS_TOKEN=$(kubectl -n authorino run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' | jq -r .access_token)
```

As Jane, send a `GET` request to **/resources**:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/resources -i
# HTTP/1.1 200 OK
```

As Jane, send a `DELETE` request to **/resources/123**:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/resources/123 -i
# HTTP/1.1 200 OK
```

As Jane, send a `GET` request to **/admin/settings**:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/admin/settings -i
# HTTP/1.1 200 OK
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-trial
```

Otherwise, delete the namespaces created in step 1 and 2:

```sh
kubectl -n authorino namespace authorino
kubectl -n authorino namespace authorino-operator
```

To uninstall the Authorino and Authorino Operator manifests, run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
