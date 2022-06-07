# User guide: Authorization with Keycloak Authorization Services

Keycloak provides a powerful set of tools (REST endpoints and administrative UIs), also known as [Keycloak Authorization Services](https://www.keycloak.org/docs/latest/authorization_services/index.html), to manage and enforce authorization, workflows for multiple access control mechanisms, including discritionary user access control and user-managed permissions.

This user guide is an example of how to use Authorino as an adapter to Keycloak Authorization Services while still relying on the reverse-proxy integration pattern, thus not involving importing an authorization library nor rebuilding the application's code.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#openid-connect-oidc-jwtjose-verification-and-validation-identityoidc">OpenID Connect (OIDC) JWT/JOSE verification and validation</a></li>
      <li>Authorization → <a href="./../features.md#open-policy-agent-opa-rego-policies-authorizationopa">Open Policy Agent (OPA) Rego policies</a></li>
    </ul>
  </summary>

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- [Keycloak](https://www.keycloak.org) server
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

In this example, Authorino will accept access tokens (JWTs) issued by the Keycloak server. These JWTs can be either normal Keycloak ID tokens or Requesting Party Tokens (RPT).

RPTs include claims about the permissions of the user regarding protected resources and scopes associated with a Keycloak authorization client that the user can access.

When the supplied access token is an RPT, Authorino will just validate whether the user's granted permissions present in the token include the requested resource ID (translated from the path) and scope (inferred from the HTTP method). If the token does not contain a `permissions` claim (i.e. it is not an RPT), Authorino will negotiate a User-Managed Access (UMA) ticket on behalf of the user and try to obtain an RPT on that UMA ticket.

In cases of asynchronous user-managed permission control, the first request to the API using a normal Keycloak ID token is denied by Authorino. The user that owns the resource acknowledges the access request in the Keycloak UI. If access is granted, the new permissions will be reflected in subsequent RPTs obtained by Authorino on behalf of the requesting party.

Whenever an RPT with proper permissions is obtained by Authorino, the RPT is supplied back to the API consumer, so it can be used in subsequent requests thus skipping new negotiations of UMA tickets.

```sh
kubectl apply -f -<<EOF
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
  authorization:
  - name: uma
    opa:
      inlineRego: |
        pat := http.send({"url":"http://talker-api:523b92b6-625d-4e1e-a313-77e7a8ae4e88@keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token","method": "post","headers":{"Content-Type":"application/x-www-form-urlencoded"},"raw_body":"grant_type=client_credentials"}).body.access_token
        resource_id := http.send({"url":concat("",["http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/authz/protection/resource_set?uri=",input.context.request.http.path]),"method":"get","headers":{"Authorization":concat(" ",["Bearer ",pat])}}).body[0]
        scope := lower(input.context.request.http.method)
        access_token := trim_prefix(input.context.request.http.headers.authorization, "Bearer ")

        default rpt = ""
        rpt = access_token { object.get(input.auth.identity, "authorization", {}).permissions }
        else = rpt_str {
          ticket := http.send({"url":"http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/authz/protection/permission","method":"post","headers":{"Authorization":concat(" ",["Bearer ",pat]),"Content-Type":"application/json"},"raw_body":concat("",["[{\"resource_id\":\"",resource_id,"\",\"resource_scopes\":[\"",scope,"\"]}]"])}).body.ticket
          rpt_str := object.get(http.send({"url":"http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token","method":"post","headers":{"Authorization":concat(" ",["Bearer ",access_token]),"Content-Type":"application/x-www-form-urlencoded"},"raw_body":concat("",["grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&ticket=",ticket,"&submit_request=true"])}).body, "access_token", "")
        }

        allow {
          permissions := object.get(io.jwt.decode(rpt)[1], "authorization", { "permissions": [] }).permissions
          permissions[i]
          permissions[i].rsid = resource_id
          permissions[i].scopes[_] = scope
        }
      allValues: true
  response:
  - name: x-keycloak
    when:
    - selector: auth.identity.authorization.permissions
      operator: eq
      value: ""
    json:
      properties:
      - name: rpt
        valueFrom: { authJSON: auth.authorization.uma.rpt }
EOF
```

## 6. Obtain an access token with the Keycloak server

The `AuthConfig` deployed in the previous step is suitable for validating access tokens requested inside the cluster. This is because Keycloak's `iss` claim added to the JWTs matches always the host used to request the token and Authorino will later try to match this host to the host that provides the OpenID Connect configuration.

Obtain an access token from within the cluster for user Jane:

```sh
ACCESS_TOKEN=$(kubectl run token --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' | jq -r .access_token)
```

If otherwise your Keycloak server is reachable from outside the cluster, feel free to obtain the token directly. Make sure the host name set in the OIDC issuer endpoint in the `AuthConfig` matches the one used to obtain the token and is as well reachable from within the cluster.

## 7. Consume the API

As Jane, try to send a `GET` request to the protected resource `/greetings/1`, owned by user John.

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1 -i
# HTTP/1.1 403 Forbidden
```

As John, log in to http://localhost:8080/auth/realms/kuadrant/account in the web browser (username: `john` / password: `p`), and grant access to the resource `greeting-1` for Jane. A pending permission request by Jane shall exist in the list of John's _Resources_.

As Jane, try to consume the protected resource `/greetings/1` again:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1 -i
# HTTP/1.1 200 OK
#
# {…
#   "headers": {…
#     "X-Keycloak": "{\"rpt\":\"<RPT>", …
```

Copy the RPT from the response and repeat the request now using the RPT to authenticate:

```sh
curl -H "Authorization: Bearer <RPT>" http://talker-api-authorino.127.0.0.1.nip.io:8000/greetings/1 -i
# HTTP/1.1 200 OK
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete authconfig/talker-api-protection
kubectl delete authorino/authorino
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/envoy/envoy-notls-deploy.yaml
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
kubectl delete namespace keycloak
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
