# User guide: Authentication with X.509 certificates and Mutual Transport Layer Security (mTLS)

Verify client X.509 certificates against trusted root CAs stored in Kubernetes `Secret`s to authenticate access to APIs protected with Authorino.

<details>
  <summary>
    <strong>Authorino features in this guide:</strong>
    <ul>
      <li>Identity verification & authentication → <a href="./../features.md#x509-client-certificate-authentication-authenticationx509">X.509 client certificate authentication</a></li>
      <li>Authorization → <a href="./../features.md#pattern-matching-authorization-authorizationpatternmatching">Pattern-matching authorization</a></li>
    </ul>
  </summary>

  Authorino can verify x509 certificates presented by clients for authentication on the request to the protected APIs, at application level.

  Trusted root Certificate Authorities (CA) are stored as Kubernetes `kubernetes.io/tls` Secrets labeled according to selectors specified in the AuthConfig, watched and cached by Authorino.

  For further details about Authorino features in general, check the [docs](./../features.md).
</details>

<br/>

## Requirements

- Kubernetes server
- [cert-manager](https://github.com/jetstack/cert-manager)

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io):

```sh
kind create cluster --name authorino-tutorial
```

Install cert-manager in the cluster:

```sh
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
```

## 1. Install the Authorino Operator

```sh
curl -sL https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/utils/install.sh | bash -s
```

## 2. Deploy Authorino

Create the TLS certificates for the Authorino service:

```sh
curl -sSL https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml | sed "s/\$(AUTHORINO_INSTANCE)/authorino/g;s/\$(NAMESPACE)/default/g" | kubectl apply -f -
```

Deploy an Authorino service:

```sh
kubectl apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  listener:
    tls:
      certSecretRef:
        name: authorino-server-cert
  oidcServer:
    tls:
      certSecretRef:
        name: authorino-oidc-server-cert
EOF
```

The command above will deploy Authorino as a separate service (as opposed to a sidecar of the protected API and other architectures), in `namespaced` reconciliation mode, and with TLS termination enabled. For other variants and deployment options, check out the [Getting Started](./../getting-started.md#step-request-an-authorino-instance) section of the docs, the [Architecture](./../architecture.md#topologies) page, and the spec for the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) CRD in the Authorino Operator repo.

## 3. Deploy the Talker API

The **Talker API** is just an echo API, included in the Authorino examples. We will use it in this guide as the service to be protected with Authorino.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## 4. Create a CA

Create a CA certificate to issue the client certificates that will be used to authenticate to consume the Talker API:

```sh
openssl req -x509 -sha256 -days 365 -nodes -newkey rsa:2048 -subj "/CN=talker-api-ca" -keyout /tmp/ca.key -out /tmp/ca.crt
```

Store the CA cert in a Kubernetes `Secret`, labeled to be discovered by Authorino:

```sh
kubectl create secret tls talker-api-ca --cert=/tmp/ca.crt --key=/tmp/ca.key
kubectl label secret talker-api-ca authorino.kuadrant.io/managed-by=authorino app=talker-api
```

## 5. Setup Envoy

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app: envoy
  name: envoy
data:
  envoy.yaml: |
    static_resources:
      listeners:
      - address:
          socket_address:
            address: 0.0.0.0
            port_value: 8000
        filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates:
                - certificate_chain: {filename: "/etc/ssl/certs/talker-api/tls.crt"}
                  private_key: {filename: "/etc/ssl/certs/talker-api/tls.key"}
                validation_context:
                  trusted_ca:
                    filename: /etc/ssl/certs/talker-api/tls.crt
          filters:
          - name: envoy.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: local
              route_config:
                name: local_route
                virtual_hosts:
                - name: local_service
                  domains: ['*']
                  routes:
                  - match: { prefix: / }
                    route: { cluster: talker-api }
              http_filters:
              - name: envoy.filters.http.ext_authz
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                  transport_api_version: V3
                  failure_mode_allow: false
                  include_peer_certificate: true
                  grpc_service:
                    envoy_grpc: { cluster_name: authorino }
                    timeout: 1s
              - name: envoy.filters.http.router
                typed_config: {}
              use_remote_address: true
      clusters:
      - name: authorino
        connect_timeout: 0.25s
        type: strict_dns
        lb_policy: round_robin
        http2_protocol_options: {}
        load_assignment:
          cluster_name: authorino
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: authorino-authorino-authorization
                    port_value: 50051
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
            common_tls_context:
              validation_context:
                trusted_ca:
                  filename: /etc/ssl/certs/authorino-ca-cert.crt
      - name: talker-api
        connect_timeout: 0.25s
        type: strict_dns
        lb_policy: round_robin
        load_assignment:
          cluster_name: talker-api
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: talker-api
                    port_value: 3000
    admin:
      access_log_path: "/tmp/admin_access.log"
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8001
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: envoy
  name: envoy
spec:
  selector:
    matchLabels:
      app: envoy
  template:
    metadata:
      labels:
        app: envoy
    spec:
      containers:
      - args:
        - --config-path /usr/local/etc/envoy/envoy.yaml
        - --service-cluster front-proxy
        - --log-level info
        - --component-log-level filter:trace,http:debug,router:debug
        command:
        - /usr/local/bin/envoy
        image: envoyproxy/envoy:v1.19-latest
        name: envoy
        ports:
        - containerPort: 8000
          name: web
        - containerPort: 8001
          name: admin
        volumeMounts:
        - mountPath: /usr/local/etc/envoy
          name: config
          readOnly: true
        - mountPath: /etc/ssl/certs/authorino-ca-cert.crt
          name: authorino-ca-cert
          readOnly: true
          subPath: ca.crt
        - mountPath: /etc/ssl/certs/talker-api
          name: talker-api-ca
          readOnly: true
      volumes:
      - configMap:
          items:
          - key: envoy.yaml
            path: envoy.yaml
          name: envoy
        name: config
      - name: authorino-ca-cert
        secret:
          defaultMode: 420
          secretName: authorino-ca-cert
      - name: talker-api-ca
        secret:
          defaultMode: 420
          secretName: talker-api-ca
---
apiVersion: v1
kind: Service
metadata:
  name: envoy
spec:
  selector:
    app: envoy
  ports:
  - name: web
    port: 8000
    protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-wildcard-host
spec:
  rules:
  - host: talker-api-authorino.127.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: envoy
            port: { number: 8000 }
        path: /
        pathType: Prefix
EOF
```

The bundle includes an `Ingress` with host name `talker-api-authorino.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, you need to forward requests on port 8000 to inside the cluster in order to actually reach the Envoy service:

```sh
kubectl port-forward deployment/envoy 8000:8000 &
```

## 6. Create the `AuthConfig`

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta2
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io
  authentication:
    "mtls":
      x509:
        selector:
          matchLabels:
            app: talker-api
  authorization:
    "acme":
      patternMatching:
        patterns:
        - selector: auth.identity.Organization
          operator: incl
          value: ACME Inc.
EOF
```

## 7. Consume the API

With a TLS certificate signed by the trusted CA:

```sh
openssl genrsa -out /tmp/aisha.key 2048
openssl req -new -key /tmp/aisha.key -out /tmp/aisha.csr -subj "/CN=aisha/C=PK/L=Islamabad/O=ACME Inc./OU=Engineering"
openssl x509 -req -in /tmp/aisha.csr -CA /tmp/ca.crt -CAkey /tmp/ca.key -CAcreateserial -out /tmp/aisha.crt -days 1 -sha256

curl -k --cert /tmp/aisha.crt --key /tmp/aisha.key https://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 200 OK
```

With a TLS certificate signed by the trusted CA, though missing an authorized Organization:

```sh
openssl genrsa -out /tmp/john.key 2048
openssl req -new -key /tmp/john.key -out /tmp/john.csr -subj "/CN=john/C=UK/L=London"
openssl x509 -req -in /tmp/john.csr -CA /tmp/ca.crt -CAkey /tmp/ca.key -CAcreateserial -out /tmp/john.crt -days 1 -sha256

curl -k --cert /tmp/john.crt --key /tmp/john.key https://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Unauthorized
```

## 8. Try the AuthConfig via raw HTTP authorization interface

Expose Authorino's raw HTTP authorization to the local host:

```sh
kubectl port-forward service/authorino-authorino-authorization 5001:5001 &
```

With a TLS certificate signed by the trusted CA:

```sh
curl -k --cert /tmp/aisha.crt --key /tmp/aisha.key -H 'Content-Type: application/json' -d '{}' https://talker-api-authorino.127.0.0.1.nip.io:5001/check -i
# HTTP/2 200
```

With a TLS certificate signed by an unknown authority:

```sh
openssl req -x509 -sha256 -days 365 -nodes -newkey rsa:2048 -subj "/CN=untrusted" -keyout /tmp/untrusted-ca.key -out /tmp/untrusted-ca.crt
openssl genrsa -out /tmp/niko.key 2048
openssl req -new -key /tmp/niko.key -out /tmp/niko.csr -subj "/CN=niko/C=JP/L=Osaka"
openssl x509 -req -in /tmp/niko.csr -CA /tmp/untrusted-ca.crt -CAkey /tmp/untrusted-ca.key -CAcreateserial -out /tmp/niko.crt -days 1 -sha256

curl -k --cert /tmp/niko.crt --key /tmp/niko.key -H 'Content-Type: application/json' -d '{}' https://talker-api-authorino.127.0.0.1.nip.io:5001/check -i
# HTTP/2 401
# www-authenticate: Basic realm="mtls"
# x-ext-auth-reason: x509: certificate signed by unknown authority
```

## 9. Revoke an entire chain of certificates

```sh
kubectl delete secret/talker-api-ca
```

Even if the deleted root certificate is still cached and accepted at the gateway, Authorino will revoke access at application level immediately.

Try with a previously accepted certificate:

```sh
curl -k --cert /tmp/aisha.crt --key /tmp/aisha.key https://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Basic realm="mtls"
# x-ext-auth-reason: x509: certificate signed by unknown authority
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
kubectl delete ingress/service
kubectl delete configmap/service
kubectl delete configmap/deployment
kubectl delete configmap/envoy
kubectl delete -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

To uninstall the Authorino Operator and manifests (CRDs, RBAC, etc), run:

```sh
kubectl delete -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

To uninstall the cert-manager, run:

```sh
kubectl delete -f kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
```
