# User guide: Using Authorino as ValidatingWebhook service

Authorino provides an interface for raw HTTP external authorization requests. This interface can be used for integrations other than the typical Envoy gRPC protocol, such as (though not limited to) using Authorino as a generic Kubernetes ValidatingWebhook service.

The rules to validate a request to the Kubernetes API – typically a `POST`, `PUT` or `DELETE` request targeting a particular Kubernetes resource or collection –, according to which either the change will be deemed accepted or not, are written in an Authorino `AuthConfig` custom resource. Authentication and authorization are performed by the Kubernetes API server as usual, with auth features of Authorino implementing the aditional validation within the scope of an `AdmissionReview` request.

This user guide provides an example of using Authorino as a Kubernetes ValidatingWebhook service that validates requests to `CREATE` and `UPDATE` Authorino `AuthConfig` resources. In other words, we will use Authorino as a validator inside the cluster that decides what is a valid AuthConfig for any application which wants to rely on Authorino to protect itself.

**The AuthConfig to validate other AuthConfigs will enforce the following rules:**
- Authorino features that cannot be used by any application in their security schemes:
  - Anonymous Access
  - Plain identity object extracted from context
  - Kubernetes authentication (TokenReview)
  - Kubernetes authorization (SubjectAccessReview)
  - Festival Wristband tokens
- Authorino features that require a RoleBinding to a specific ClusterRole in the 'authorino' namespace, to be used in a AuthConfig:
  - Authorino API key authentication
- All metadata pulled from external sources must be cached for precisely 5 minutes (300 seconds)

For convinience, the same instance of Authorino used to enforce the AuthConfig associated with the validating webhook will also be targeted for the sample AuthConfigs created to test the validation. For using different instances of Authorino for the validating webhook and for protecting applications behind a proxy, check out the section about [sharding](./../architecture.md#sharding) in the docs. There is also a [user guide](./sharding.md) on the topic, with concrete examples.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#plain-identityplain">Plain</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#kubernetes-tokenreview-identitykubernetes">Kubernetes TokenReview</a></li>
      <li>Identity verification & authentication → <a href="./../features.md#api-key-identityapikey">API key</a></li>
      <li>External auth metadata → <a href="./../features.md#http-getget-by-post-metadatahttp">HTTP GET/GET-by-POST</a></li>
      <li>Authorization → <a href="./../features.md#kubernetes-subjectaccessreview-authorizationkubernetes">Kubernetes SubjectAccessReview</a></li>
      <li>Authorization → <a href="./../features.md#open-policy-agent-opa-rego-policies-authorizationopa">Open Policy Agent (OPA) Rego policies</a></li>
      <li>Dynamic response → <a href="./../features.md#festival-wristband-tokens-responsewristband">Festival Wristband tokens</a></li>
      <li>Common feature → <a href="./../features.md#common-feature-conditions-when">Conditions</a></li>
      <li>Common feature → <a href="./../features.md#common-feature-priorities">Priorities</a></li>
    </ul>
  </summary>

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- [cert-manager](https://github.com/jetstack/cert-manager)
- Auth server / Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-tutorial
```

Install cert-manager:

```sh
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
```

Deploy a Keycloak server preloaded with all the realm settings required for this guide:

```sh
kubectl create namespace keycloak
kubectl -n keycloak apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
```

## 1. Install the Authorino Operator

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

## 2. Deploy Authorino

Create the namespace:

```sh
kubectl create namespace authorino
```

Create the TLS certificates:

```sh
curl -sSL https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml | sed "s/\$(AUTHORINO_INSTANCE)/authorino/g;s/\$(NAMESPACE)/authorino/g" | kubectl -n authorino apply -f -
```

Create the Authorino instance:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  clusterWide: true
  listener:
    ports:
      grpc: 50051
      http: 5001 # for admissionreview requests sent by the kubernetes api server
    tls:
      certSecretRef:
        name: authorino-server-cert
  oidcServer:
    tls:
      certSecretRef:
        name: authorino-oidc-server-cert
EOF
```

The command above will deploy Authorino as a separate service (as oposed to a sidecar of the protected API and other architectures), in `cluster-wide` reconciliation mode, and with TLS termination enabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#2-deploy-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 3. Create the `AuthConfig` and related `ClusterRole`

Create the `AuthConfig`:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: authconfig-validator
spec:
  # admissionreview requests will be sent to this host name
  hosts:
  - authorino-authorino-authorization.authorino.svc

  # because we're using a single authorino instance for the validating webhook and to protect the user applications,
  # skip operations related to this one authconfig in the 'authorino' namespace
  when:
  - selector: context.request.http.body.@fromstr|request.object.metadata.namespace
    operator: neq
    value: authorino

  # kubernetes admissionreviews carry info about the authenticated user
  identity:
  - name: k8s-userinfo
    plain:
      authJSON: context.request.http.body.@fromstr|request.userInfo

  authorization:
  - name: features
    opa:
      inlineRego: |
        authconfig = json.unmarshal(input.context.request.http.body).request.object

        forbidden { count(object.get(authconfig.spec, "identity", [])) == 0 }
        forbidden { authconfig.spec.identity[_].anonymous }
        forbidden { authconfig.spec.identity[_].kubernetes }
        forbidden { authconfig.spec.identity[_].plain }
        forbidden { authconfig.spec.authorization[_].kubernetes }
        forbidden { authconfig.spec.response[_].wristband }

        apiKey { authconfig.spec.identity[_].apiKey }

        allow { count(authconfig.spec.identity) > 0; not forbidden }
      allValues: true

  - name: apikey-authn-requires-k8s-role-binding
    priority: 1
    when:
    - selector: auth.authorization.features.apiKey
      operator: eq
      value: "true"
    kubernetes:
      user:
        valueFrom: { authJSON: auth.identity.username }
      resourceAttributes:
        namespace: { value: authorino }
        group: { value: authorino.kuadrant.io }
        resource: { value: authconfigs-with-apikeys }
        verb: { value: create }

  - name: metadata-cache-ttl
    priority: 1
    opa:
      inlineRego: |
        invalid_ttl = input.auth.authorization.features.authconfig.spec.metadata[_].cache.ttl != 300
        allow { not invalid_ttl }
EOF
```

Define a `ClusterRole` to control the usage of protected features of Authorino:

```sh
kubectl apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: authorino-apikey
rules:
- apiGroups: ["authorino.kuadrant.io"]
  resources: ["authconfigs-with-apikeys"] # not a real k8s resource
  verbs: ["create"]
EOF
```

## 4. Create the `ValidatingWebhookConfiguration`

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: authconfig-authz
  annotations:
    cert-manager.io/inject-ca-from: authorino/authorino-ca-cert
webhooks:
- name: check-authconfig.authorino.kuadrant.io
  clientConfig:
    service:
      namespace: authorino
      name: authorino-authorino-authorization
      port: 5001
      path: /check
  rules:
  - apiGroups: ["authorino.kuadrant.io"]
    apiVersions: ["v1beta1"]
    resources: ["authconfigs"]
    operations: ["CREATE", "UPDATE"]
    scope: Namespaced
  sideEffects: None
  admissionReviewVersions: ["v1"]
EOF
```

## 5. Try it out

Create a namespace:

```sh
kubectl create namespace myapp
```

### With a valid `AuthConfig`

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: keycloak
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
EOF
# authconfig.authorino.kuadrant.io/myapp-protection created
```

### With forbidden features

Anonymous access:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta1\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"hosts\":[\"myapp.io\"]}}\n"}},"spec":{"identity":null}}
# to:
# Resource: "authorino.kuadrant.io/v1beta1, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta1, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: anonymous-access
    anonymous: {}
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta1\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"hosts\":[\"myapp.io\"],\"identity\":[{\"anonymous\":{},\"name\":\"anonymous-access\"}]}}\n"}},"spec":{"identity":[{"anonymous":{},"name":"anonymous-access"}]}}
# to:
# Resource: "authorino.kuadrant.io/v1beta1, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta1, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Kuberentes TokenReview:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: k8s-tokenreview
    kubernetes:
      audiences: ["myapp"]
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta1\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"hosts\":[\"myapp.io\"],\"identity\":[{\"kubernetes\":{\"audiences\":[\"myapp\"]},\"name\":\"k8s-tokenreview\"}]}}\n"}},"spec":{"identity":[{"kubernetes":{"audiences":["myapp"]},"name":"k8s-tokenreview"}]}}
# to:
# Resource: "authorino.kuadrant.io/v1beta1, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta1, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Plain identity extracted from context:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: envoy-jwt-authn
    plain:
      authJSON: context.metadata_context.filter_metadata.envoy\.filters\.http\.jwt_authn|verified_jwt
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta1\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"hosts\":[\"myapp.io\"],\"identity\":[{\"name\":\"envoy-jwt-authn\",\"plain\":{\"authJSON\":\"context.metadata_context.filter_metadata.envoy\\\\.filters\\\\.http\\\\.jwt_authn|verified_jwt\"}}]}}\n"}},"spec":{"identity":[{"name":"envoy-jwt-authn","plain":{"authJSON":"context.metadata_context.filter_metadata.envoy\\.filters\\.http\\.jwt_authn|verified_jwt"}}]}}
# to:
# Resource: "authorino.kuadrant.io/v1beta1, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta1, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Kubernetes SubjectAccessReview:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: keycloak
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
  authorization:
  - name: k8s-subjectaccessreview
    kubernetes:
      user:
        valueFrom: { authJSON: auth.identity.sub }
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta1\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"authorization\":[{\"kubernetes\":{\"user\":{\"valueFrom\":{\"authJSON\":\"auth.identity.sub\"}}},\"name\":\"k8s-subjectaccessreview\"}],\"hosts\":[\"myapp.io\"],\"identity\":[{\"name\":\"keycloak\",\"oidc\":{\"endpoint\":\"http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant\"}}]}}\n"}},"spec":{"authorization":[{"kubernetes":{"user":{"valueFrom":{"authJSON":"auth.identity.sub"}}},"name":"k8s-subjectaccessreview"}],"identity":[{"name":"keycloak","oidc":{"endpoint":"http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant"}}]}}
# to:
# Resource: "authorino.kuadrant.io/v1beta1, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta1, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Festival Wristband tokens:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: v1
kind: Secret
metadata:
  name: wristband-signing-key
stringData:
  key.pem: |
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIDHvuf81gVlWGo0hmXGTAnA/HVxGuH8vOc7/8jewcVvqoAoGCCqGSM49
    AwEHoUQDQgAETJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZxJKDysoGwn
    cnUvHIu23SgW+Ee9lxSmZGhO4eTdQeKxMA==
    -----END EC PRIVATE KEY-----
type: Opaque
---
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: keycloak
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
  response:
  - name: wristband
    wristband:
      issuer: http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/myapp/myapp-protection/wristband
      signingKeyRefs:
      - algorithm: ES256
        name: wristband-signing-key
EOF
# secret/wristband-signing-key created
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta1\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"hosts\":[\"myapp.io\"],\"identity\":[{\"name\":\"keycloak\",\"oidc\":{\"endpoint\":\"http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant\"}}],\"response\":[{\"name\":\"wristband\",\"wristband\":{\"issuer\":\"http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/myapp/myapp-protection/wristband\",\"signingKeyRefs\":[{\"algorithm\":\"ES256\",\"name\":\"wristband-signing-key\"}]}}]}}\n"}},"spec":{"identity":[{"name":"keycloak","oidc":{"endpoint":"http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant"}}],"response":[{"name":"wristband","wristband":{"issuer":"http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/myapp/myapp-protection/wristband","signingKeyRefs":[{"algorithm":"ES256","name":"wristband-signing-key"}]}}]}}
# to:
# Resource: "authorino.kuadrant.io/v1beta1, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta1, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

### With features that require additional permissions

Before adding the required permissions:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: api-key
    apiKey:
      selector:
        matchLabels: { app: myapp }
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta1\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"hosts\":[\"myapp.io\"],\"identity\":[{\"apiKey\":{\"selector\":{\"matchLabels\":{\"app\":\"myapp\"}}},\"name\":\"api-key\"}]}}\n"}},"spec":{"identity":[{"apiKey":{"selector":{"matchLabels":{"app":"myapp"}}},"name":"api-key"}]}}
# to:
# Resource: "authorino.kuadrant.io/v1beta1, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta1, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Not authorized: unknown reason
```

Add the required permissions:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: authorino-apikey
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: authorino-apikey
subjects:
- kind: User
  name: kubernetes-admin
EOF
# rolebinding.rbac.authorization.k8s.io/authorino-apikey created
```

After adding the required permissions:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: api-key
    apiKey:
      selector:
        matchLabels: { app: myapp }
EOF
# authconfig.authorino.kuadrant.io/myapp-protection configured
```

## With features that require specific property validation

Invalid:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: keycloak
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
  metadata:
  - name: external-source
    http:
      endpoint: http://metadata.io
      method: GET
    cache:
      key: { value: global }
      ttl: 60
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta1\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"hosts\":[\"myapp.io\"],\"identity\":[{\"name\":\"keycloak\",\"oidc\":{\"endpoint\":\"http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant\"}}],\"metadata\":[{\"cache\":{\"key\":{\"value\":\"global\"},\"ttl\":60},\"http\":{\"endpoint\":\"http://metadata.io\",\"method\":\"GET\"},\"name\":\"external-source\"}]}}\n"}},"spec":{"identity":[{"name":"keycloak","oidc":{"endpoint":"http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant"}}],"metadata":[{"cache":{"key":{"value":"global"},"ttl":60},"http":{"endpoint":"http://metadata.io","method":"GET"},"name":"external-source"}]}}
# to:
# Resource: "authorino.kuadrant.io/v1beta1, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta1, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Valid:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  identity:
  - name: keycloak
    oidc:
      endpoint: http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/kuadrant
  metadata:
  - name: external-source
    http:
      endpoint: http://metadata.io
      method: GET
    cache:
      key: { value: global }
      ttl: 300
EOF
# authconfig.authorino.kuadrant.io/myapp-protection configured
```

## Cleanup

If you have started a Kubernetes cluster locally with Kind to try this user guide, delete it by running:

```sh
kind delete cluster --name authorino-tutorial
```

Otherwise, delete the resources created in each step:

```sh
kubectl delete namespace myapp
kubectl delete namespace authorino
kubectl delete namespace clusterrole/authorino-apikey
kubectl delete namespace keycloak
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
