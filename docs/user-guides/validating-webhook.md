# User guide: Using Authorino as ValidatingWebhook service

Authorino provides an interface for raw HTTP external authorization requests. This interface can be used for integrations other than the typical Envoy gRPC protocol, such as (though not limited to) using Authorino as a generic Kubernetes ValidatingWebhook service.

The rules to validate a request to the Kubernetes API – typically a `POST`, `PUT` or `DELETE` request targeting a particular Kubernetes resource or collection –, according to which either the change will be deemed accepted or not, are written in an Authorino `AuthConfig` custom resource. Authentication and authorization are performed by the Kubernetes API server as usual, with auth features of Authorino implementing the additional validation within the scope of an `AdmissionReview` request.

This user guide provides an example of using Authorino as a Kubernetes ValidatingWebhook service that validates requests to `CREATE` and `UPDATE` Authorino `AuthConfig` resources. In other words, we will use Authorino as a validator inside the cluster that decides what is a valid AuthConfig for any application which wants to rely on Authorino to protect itself.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Identity verification & authentication → [Plain](../features.md#plain-authenticationplain)
  - Identity verification & authentication → [Kubernetes TokenReview](../features.md#kubernetes-tokenreview-authenticationkubernetestokenreview)
  - Identity verification & authentication → [API key](../features.md#api-key-authenticationapikey)
  - External auth metadata → [HTTP GET/GET-by-POST](../features.md#http-getget-by-post-metadatahttp)
  - Authorization → [Kubernetes SubjectAccessReview](../features.md#kubernetes-subjectaccessreview-authorizationkubernetessubjectaccessreview)
  - Authorization → [Open Policy Agent (OPA) Rego policies](../features.md#open-policy-agent-opa-rego-policies-authorizationopa)
  - Dynamic response → [Festival Wristband tokens](../features.md#festival-wristband-tokens-responsesuccessheadersdynamicmetadatawristband)
  - Common feature → [Conditions](../features.md#common-feature-conditions-when)
  - Common feature → [Priorities](../features.md#common-feature-priorities)

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)
- Identity Provider (IdP) that implements OpenID Connect authentication and OpenID Connect Discovery (e.g. [Keycloak](https://www.keycloak.org))

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
```

Deploy the identity provider and authentication server. For the examples in this guide, we are going to use a Keycloak server preloaded with all required realm settings.

The Keycloak server is only needed for trying out validating AuthConfig resources that use the authentication server.

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
        <p>If you are a user of <a href="https://kuadrant.io">Kuadrant</a> you may already have Authorino installed and running. In this case, skip straight to step ❸.</p>
        <p>At step ❺, alternatively to creating an <code>AuthConfig</code> custom resource, you may create a Kuadrant <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> one. The schema of the AuthConfig's <code>spec</code> matches the one of the AuthPolicy's, except <code>spec.host</code>, which is not available in the Kuadrant AuthPolicy. Host names in a Kuadrant AuthPolicy are inferred automatically from the Kubernetes network object referred in <code>spec.targetRef</code> and route selectors declared in the policy.</p>
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

Create the namespace:

```sh
kubectl create namespace authorino
```

Create the TLS certificates:

```sh
curl -sSL https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml | sed "s/\$(AUTHORINO_INSTANCE)/authorino/g;s/\$(NAMESPACE)/authorino/g" | kubectl -n authorino apply -f -
```

Create the Authorino instance:

The following command will request an instance of Authorino as a separate service[^1] that watches for `AuthConfig` resources cluster-wide[^2], with TLS enabled[^3].

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

[^1]: In contrast to a dedicated sidecar of the protected service and other architectures. Check out __Architecture > [Topologies](../architecture.md#topologies)__ for all options.
[^2]: `cluster-wide` reconciliation mode. See [Cluster-wide vs. Namespaced instances](../architecture.md#cluster-wide-vs-namespaced-instances).
[^3]: For other variants and deployment options, check out [Getting Started](../getting-started.md#step-request-an-authorino-instance), as well as the [`Authorino`](https://github.com/kuadrant/authorino-operator#the-authorino-custom-resource-definition-crd) CRD specification.

For convenience, the same instance of Authorino pointed as the validating webhook will also be targeted for the sample AuthConfigs created to test the validation. For using different instances of Authorino for the validating webhook and for protecting applications behind a proxy, check out the section about [sharding](../architecture.md#sharding) in the docs. There is also a [user guide](sharding.md) on the topic, with concrete examples.

## ❸ Create the `AuthConfig` and related `ClusterRole`

Create the `AuthConfig` with the auth rules to validate other AuthConfig resources applied to the cluster.

The AuthConfig to validate other AuthConfigs will enforce the following rules:
- Authorino features that cannot be used by any application in their security schemes:
  - Anonymous Access
  - Plain identity object extracted from context
  - Kubernetes authentication (TokenReview)
  - Kubernetes authorization (SubjectAccessReview)
  - Festival Wristband tokens
- Authorino features that require a RoleBinding to a specific ClusterRole in the 'authorino' namespace, to be used in a AuthConfig:
  - Authorino API key authentication
- All metadata pulled from external sources must be cached for precisely 5 minutes (300 seconds)

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
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
  authentication:
    "k8s-userinfo":
      plain:
        selector: context.request.http.body.@fromstr|request.userInfo

  authorization:
    "features":
      opa:
        rego: |
          authconfig = json.unmarshal(input.context.request.http.body).request.object

          forbidden { count(object.get(authconfig.spec, "authentication", [])) == 0 }
          forbidden { authconfig.spec.authentication[_].anonymous }
          forbidden { authconfig.spec.authentication[_].kubernetesTokenReview }
          forbidden { authconfig.spec.authentication[_].plain }
          forbidden { authconfig.spec.authorization[_].kubernetesSubjectAccessReview }
          forbidden { authconfig.spec.response.success.headers[_].wristband }

          apiKey { authconfig.spec.authentication[_].apiKey }

          allow { count(authconfig.spec.authentication) > 0; not forbidden }
        allValues: true

    "apikey-authn-requires-k8s-role-binding":
      priority: 1
      when:
      - selector: auth.authorization.features.apiKey
        operator: eq
        value: "true"
      kubernetesSubjectAccessReview:
        user:
          selector: auth.identity.username
        resourceAttributes:
          namespace: { value: authorino }
          group: { value: authorino.kuadrant.io }
          resource: { value: authconfigs-with-apikeys }
          verb: { value: create }

    "metadata-cache-ttl":
      priority: 1
      opa:
        rego: |
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

## ❹ Create the `ValidatingWebhookConfiguration`

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
    apiVersions: ["v1beta2"]
    resources: ["authconfigs"]
    operations: ["CREATE", "UPDATE"]
    scope: Namespaced
  sideEffects: None
  admissionReviewVersions: ["v1"]
EOF
```

## ❺ Try it out

Create a namespace:

```sh
kubectl create namespace myapp
```

### With a valid `AuthConfig`

<table>
  <tbody>
    <tr>
      <td>
        <b><i>Kuadrant users –</i></b>
        For this and other example AuthConfigs below, if you create a Kuadrant <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> instead, the output of the commands shall differ. The requested AuthPolicy may be initially accepted, but its state will turn ready or not ready depending on whether the corresponding AuthConfig requested by Kuadrant is accepted or rejected, according to the validating webhook rules. Check the state of the resources to confirm.
        For more, see <a href="https://docs.kuadrant.io/kuadrant-operator/doc/auth">Kuadrant auth</a>.
      </td>
    </tr>
  </tbody>
</table>

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "keycloak":
      jwt:
        issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
EOF
# authconfig.authorino.kuadrant.io/myapp-protection created
```

### With forbidden features

Anonymous access:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta2\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"hosts\":[\"myapp.io\"]}}\n"}},"spec":{"authentication":null}}
# to:
# Resource: "authorino.kuadrant.io/v1beta2, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta2, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": error when patching "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "anonymous-access":
      anonymous: {}
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta2\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"authentication\":{\"anonymous-access\":{\"anonymous\":{}}},\"hosts\":[\"myapp.io\"]}}\n"}},"spec":{"authentication":{"anonymous-access":{"anonymous":{}},"keycloak":null}}}
# to:
# Resource: "authorino.kuadrant.io/v1beta2, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta2, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": error when patching "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Kubernetes TokenReview:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "k8s-tokenreview":
      kubernetesTokenReview:
        audiences: ["myapp"]
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta2\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"authentication\":{\"k8s-tokenreview\":{\"kubernetesTokenReview\":{\"audiences\":[\"myapp\"]}}},\"hosts\":[\"myapp.io\"]}}\n"}},"spec":{"authentication":{"k8s-tokenreview":{"kubernetesTokenReview":{"audiences":["myapp"]}},"keycloak":null}}}
# to:
# Resource: "authorino.kuadrant.io/v1beta2, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta2, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": error when patching "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Plain identity extracted from context:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "envoy-jwt-authn":
      plain:
        selector: context.metadata_context.filter_metadata.envoy\.filters\.http\.jwt_authn|verified_jwt
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta2\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"authentication\":{\"envoy-jwt-authn\":{\"plain\":{\"selector\":\"context.metadata_context.filter_metadata.envoy\\\\.filters\\\\.http\\\\.jwt_authn|verified_jwt\"}}},\"hosts\":[\"myapp.io\"]}}\n"}},"spec":{"authentication":{"envoy-jwt-authn":{"plain":{"selector":"context.metadata_context.filter_metadata.envoy\\.filters\\.http\\.jwt_authn|verified_jwt"}},"keycloak":null}}}
# to:
# Resource: "authorino.kuadrant.io/v1beta2, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta2, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": error when patching "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Kubernetes SubjectAccessReview:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "keycloak":
      jwt:
        issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
  authorization:
    "k8s-subjectaccessreview":
      kubernetesSubjectAccessReview:
        user:
          selector: auth.identity.sub
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta2\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"authentication\":{\"keycloak\":{\"jwt\":{\"issuerUrl\":\"http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant\"}}},\"authorization\":{\"k8s-subjectaccessreview\":{\"kubernetesSubjectAccessReview\":{\"user\":{\"selector\":\"auth.identity.sub\"}}}},\"hosts\":[\"myapp.io\"]}}\n"}},"spec":{"authorization":{"k8s-subjectaccessreview":{"kubernetesSubjectAccessReview":{"user":{"selector":"auth.identity.sub"}}}}}}
# to:
# Resource: "authorino.kuadrant.io/v1beta2, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta2, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": error when patching "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
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
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "keycloak":
      jwt:
        issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
  response:
    success:
      headers:
        "wristband":
          wristband:
            issuer: http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/myapp/myapp-protection/wristband
            signingKeyRefs:
            - algorithm: ES256
              name: wristband-signing-key
EOF
# secret/wristband-signing-key created
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta2\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"authentication\":{\"keycloak\":{\"jwt\":{\"issuerUrl\":\"http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant\"}}},\"hosts\":[\"myapp.io\"],\"response\":{\"success\":{\"headers\":{\"wristband\":{\"wristband\":{\"issuer\":\"http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/myapp/myapp-protection/wristband\",\"signingKeyRefs\":[{\"algorithm\":\"ES256\",\"name\":\"wristband-signing-key\"}]}}}}}}}\n"}},"spec":{"response":{"success":{"headers":{"wristband":{"wristband":{"issuer":"http://authorino-authorino-oidc.authorino.svc.cluster.local:8083/myapp/myapp-protection/wristband","signingKeyRefs":[{"algorithm":"ES256","name":"wristband-signing-key"}]}}}}}}}
# to:
# Resource: "authorino.kuadrant.io/v1beta2, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta2, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": error when patching "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

### With features that require additional permissions

Before adding the required permissions:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "api-key":
      apiKey:
        selector:
          matchLabels: { app: myapp }
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta2\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"authentication\":{\"api-key\":{\"apiKey\":{\"selector\":{\"matchLabels\":{\"app\":\"myapp\"}}}}},\"hosts\":[\"myapp.io\"]}}\n"}},"spec":{"authentication":{"api-key":{"apiKey":{"selector":{"matchLabels":{"app":"myapp"}}}},"keycloak":null}}}
# to:
# Resource: "authorino.kuadrant.io/v1beta2, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta2, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": error when patching "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Not authorized: unknown reason
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
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "api-key":
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
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "keycloak":
      jwt:
        issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
  metadata:
    "external-source":
      http:
        url: http://metadata.io
      cache:
        key: { value: global }
        ttl: 60
EOF
# Error from server: error when applying patch:
# {"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"authorino.kuadrant.io/v1beta2\",\"kind\":\"AuthConfig\",\"metadata\":{\"annotations\":{},\"name\":\"myapp-protection\",\"namespace\":\"myapp\"},\"spec\":{\"authentication\":{\"keycloak\":{\"jwt\":{\"issuerUrl\":\"http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant\"}}},\"hosts\":[\"myapp.io\"],\"metadata\":{\"external-source\":{\"cache\":{\"key\":{\"value\":\"global\"},\"ttl\":60},\"http\":{\"url\":\"http://metadata.io\"}}}}}\n"}},"spec":{"authentication":{"api-key":null,"keycloak":{"jwt":{"issuerUrl":"http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant"}}},"metadata":{"external-source":{"cache":{"key":{"value":"global"},"ttl":60},"http":{"url":"http://metadata.io"}}}}}
# to:
# Resource: "authorino.kuadrant.io/v1beta2, Resource=authconfigs", GroupVersionKind: "authorino.kuadrant.io/v1beta2, Kind=AuthConfig"
# Name: "myapp-protection", Namespace: "myapp"
# for: "STDIN": error when patching "STDIN": admission webhook "check-authconfig.authorino.kuadrant.io" denied the request: Unauthorized
```

Valid:

```sh
kubectl -n myapp apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: myapp-protection
spec:
  hosts:
  - myapp.io
  authentication:
    "keycloak":
      jwt:
        issuerUrl: http://keycloak.keycloak.svc.cluster.local:8080/realms/kuadrant
  metadata:
    "external-source":
      http:
        url: http://metadata.io
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
kubectl delete clusterrole authorino-apikey
kubectl delete namespace keycloak
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```
