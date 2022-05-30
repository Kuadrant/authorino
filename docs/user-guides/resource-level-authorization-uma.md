# User guide: Resource-level authorization with User-Managed Access (UMA) resource registry

Fetch resource metadata relevant for your authorization policies from Keycloak authorization clients, unsing User-Managed Access (UMA) protocol.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>External auth metadata → <a href="./../features.md#user-managed-access-uma-resource-registry-metadatauma">User-Managed Access (UMA) resource registry</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc">OpenID Connect (OIDC) JWT/JOSE verification and validation</a></li>
      <li>Authorization → <a href="./../features.md#open-policy-agent-opa-rego-policies-authorizationopa">Open Policy Agent (OPA) Rego policies</a></li>
    </ul>
  </summary>

  Check out as well the user guides about [OpenID Connect Discovery and authentication with JWTs](./oidc-jwt-authentication.md) and [Open Policy Agent (OPA) Rego policies](./opa-authorization.md).

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- Auth server / Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))
- [jq](https://stedolan.github.io/jq), to extract parts of JSON responses

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-tutorial
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

## 2. Deploy the Talker API

The **Talker API** is just an echo API, included in the Authorino examples. We will use it in this guide as the service to be protected with Authorino.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## 3. Deploy Authorino

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

The command above will deploy Authorino as a separate service (as oposed to a sidecar of the protected API and other architectures), in `namespaced` reconciliation mode, and with TLS termination disabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 4. Setup Envoy

The following bundle from the Authorino examples (manifest referred in the command below) is to apply Envoy configuration and deploy Envoy proxy, that wire up the Talker API behind the reverse-proxy and external authorization with the Authorino instance.

For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](./../getting-started.md#1-setup-envoy) page. For a simpler and straighforward way to manage an API, without having to manually install or configure Envoy and Authorino, check out [Kuadrant](https://github.com/kuadrant).

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
```

The bundle also creates an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`, but if you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl port-forward deployment/envoy 8000:8000 &
```

## 5. Create the `AuthConfig`

This user guide's implementation for resource-level authorization leverages part of Keycloak's User-Managed Access (UMA) support. Authorino will fetch resource attributes stored in a Keycloak resource server client.

The Keycloak server also provides the identities. The `sub` claim of the Keycloak-issued ID tokens must match the owner of the requested resource, identitfied by the URI of the request.

Create a required secret, used by Authorino to start the authentication with the UMA registry.

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: talker-api-uma-credentials
stringData:
  clientID: talker-api
  clientSecret: 523b92b6-625d-4e1e-a313-77e7a8ae4e88
type: Opaque
EOF
```

Create the config:

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io
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
  metadata:
  - name: resource-data
    uma:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
      credentialsRef:
        name: talker-api-uma-credentials
  authorization:
  - name: owned-resources
    opa:
      inlineRego: |
        COLLECTIONS = ["greetings"]

        http_request = input.context.request.http
        http_method = http_request.method
        requested_path_sections = split(trim_left(trim_right(http_request.path, "/"), "/"), "/")

        get { http_method == "GET" }
        post { http_method == "POST" }
        put { http_method == "PUT" }
        delete { http_method == "DELETE" }

        valid_collection { COLLECTIONS[_] == requested_path_sections[0] }

        collection_endpoint {
          valid_collection
          count(requested_path_sections) == 1
        }

        resource_endpoint {
          valid_collection
          some resource_id
          requested_path_sections[1] = resource_id
        }

        identity_owns_the_resource {
          identity := input.auth.identity
          resource_attrs := object.get(input.auth.metadata, "resource-data", [])[0]
          resource_owner := object.get(object.get(resource_attrs, "owner", {}), "id", "")
          resource_owner == identity.sub
        }

        allow { get;    collection_endpoint }
        allow { post;   collection_endpoint }
        allow { get;    resource_endpoint; identity_owns_the_resource }
        allow { put;    resource_endpoint; identity_owns_the_resource }
        allow { delete; resource_endpoint; identity_owns_the_resource }
EOF
```

The OPA policy `owned-resource` above enforces that all users can send GET and POST requests to `/greetings`, while only resource owners can send GET, PUT and DELETE requests to `/greetings/{resource-id}`.


## 6. Obtain access tokens with the Keycloak server and consume the API

### Obtain an access token as John and consume the API

Obtain an access token for user John (owner of the resource `/greetings/1` in the UMA registry):

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster:

```sh
ACCESS_TOKEN=$(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' | jq -r .access_token)
```

If otherwise your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

As John, send requests to the API:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings
# HTTP/1.1 200 OK

curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1
# HTTP/1.1 200 OK

curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1
# HTTP/1.1 200 OK

curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/2 -i
# HTTP/1.1 403 Forbidden
```

### Obtain an access token as Jane and consume the API

Obtain an access token for user Jane (owner of the resource `/greetings/2` in the UMA registry):

```sh
ACCESS_TOKEN=$(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' | jq -r .access_token)
```

As Jane, send requests to the API:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings
# HTTP/1.1 200 OK

curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1 -i
# HTTP/1.1 403 Forbidden

curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1 -i
# HTTP/1.1 403 Forbidden

curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/2
# HTTP/1.1 200 OK
```

### Obtain an access token as Peter and consume the API

Obtain an access token for user Peter (does not own any resource in the UMA registry):

```sh
ACCESS_TOKEN=$(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=peter' -d 'password=p' | jq -r .access_token)
```

As Jane, send requests to the API:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings
# HTTP/1.1 200 OK

curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1 -i
# HTTP/1.1 403 Forbidden

curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1 -i
# HTTP/1.1 403 Forbidden

curl -H "Authorization: Bearer $ACCESS_TOKEN" -X DELETE http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/2 -i
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
kubectl delete secret/talker-api-uma-credentials
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete namespace keycloak
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
