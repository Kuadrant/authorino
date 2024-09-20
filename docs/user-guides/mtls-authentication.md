# User guide: Authentication with X.509 certificates and Mutual Transport Layer Security (mTLS)

Verify client X.509 certificates against trusted root CAs stored in Kubernetes `Secret`s to authenticate access to APIs protected with Authorino.

<details markdown="1">
  <summary>Authorino capabilities featured in this guide</summary>

  - Identity verification & authentication → [X.509 client certificate authentication](../features.md#x509-client-certificate-authentication-authenticationx509)
  - Authorization → [Pattern-matching authorization](../features.md#pattern-matching-authorization-authorizationpatternmatching)

  Authorino can verify x509 certificates presented by clients for authentication on the request to the protected APIs, at application level.

  Trusted root Certificate Authorities (CA) are stored as Kubernetes `kubernetes.io/tls` Secrets labeled according to selectors specified in the AuthConfig, watched and cached by Authorino.

  For further details about Authorino features in general, check the [docs](../features.md).
</details>

## Requirements

- Kubernetes server with permissions to install cluster-scoped resources (operator, CRDs and RBAC)

If you do not own a Kubernetes server already and just want to try out the steps in this guide, you can create a local containerized cluster by executing the command below. In this case, the main requirement is having [Kind](https://kind.sigs.k8s.io) installed, with either [Docker](https://www.docker.com/) or [Podman](https://podman.io/).

```sh
kind create cluster --name authorino-tutorial
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
        <p>If you are a user of <a href="https://kuadrant.io">Kuadrant</a> and already have your workload cluster configured and sample service application deployed, as well as your Gateway API network resources applied to route traffic to your service, skip straight to step ❻.</p>
        <p>At step ❻, instead of creating an <code>AuthConfig</code> custom resource, create a Kuadrant <a href="https://docs.kuadrant.io/kuadrant-operator/doc/reference/authpolicy"><code>AuthPolicy</code></a> one. The schema of the AuthConfig's <code>spec</code> matches the one of the AuthPolicy's, except <code>spec.host</code>, which is not available in the Kuadrant AuthPolicy. Host names in a Kuadrant AuthPolicy are inferred automatically from the Kubernetes network object referred in <code>spec.targetRef</code> and route selectors declared in the policy.</p>
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

The following commands will request an instance of Authorino as a separate service[^1] that watches for `AuthConfig` resources in the `default` namespace[^2], with TLS enabled[^3].

Create the TLS certificates for the Authorino service:

```sh
curl -sSL https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml | sed "s/\$(AUTHORINO_INSTANCE)/authorino/g;s/\$(NAMESPACE)/default/g" | kubectl apply -f -
```

Request the Authorino instance:

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

[^1]: In contrast to a dedicated sidecar of the protected service and other architectures. Check out __Architecture > [Topologies](../architecture.md#topologies)__ for all options.
[^2]: `namespaced` reconciliation mode. See [Cluster-wide vs. Namespaced instances](../architecture.md#cluster-wide-vs-namespaced-instances).
[^3]: For other variants and deployment options, check out [Getting Started](../getting-started.md#step-request-an-authorino-instance), as well as the [`Authorino`](https://github.com/kuadrant/authorino-operator#the-authorino-custom-resource-definition-crd) CRD specification.

## ❸ Deploy the Talker API

The **Talker API** is a simple HTTP service that echoes back in the response whatever it gets in the request. We will use it in this guide as the sample service to be protected by Authorino.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## ❹ Create a CA

Create a CA (Certificate Authority) certificate to issue the client certificates that will be used to authenticate clients that send requests to the Talker API:

```sh
openssl req -x509 -sha512 -nodes \
  -days 365 \
  -newkey rsa:4096 \
  -subj "/CN=talker-api-ca" \
  -addext basicConstraints=CA:TRUE \
  -addext keyUsage=digitalSignature,keyCertSign \
  -keyout /tmp/ca.key \
  -out /tmp/ca.crt
```

Store the CA cert in a Kubernetes `Secret`, labeled to be discovered by Authorino and to be mounted in the file system of the Envoy container:

```sh
kubectl create secret tls talker-api-ca --cert=/tmp/ca.crt --key=/tmp/ca.key
kubectl label secret talker-api-ca authorino.kuadrant.io/managed-by=authorino app=talker-api
```

Prepare an extension file for the client certificate signing requests:

```sh
cat > /tmp/x509v3.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
extendedKeyUsage=clientAuth
EOF
```

## ❺ Setup Envoy

The following command deploys the [Envoy](https://envoyproxy.io/) proxy and configuration to wire up the Talker API behind the reverse-proxy, with external authorization enabled with the Authorino instance.[^4]

[^4]: For details and instructions to setup Envoy manually, see _Protect a service > Setup Envoy_ in the [Getting Started](../getting-started.md#step-setup-envoy) page. If you are running your ingress gateway in Kubernetes and wants to avoid setting up and configuring your proxy manually, check out [Kuadrant](https://kuadrant.io).

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
            port_value: 8443
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
        - containerPort: 8443
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
    port: 8443
    protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-wildcard-host
spec:
  rules:
  - host: talker-api.127.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: envoy
            port: { number: 8443 }
        path: /
        pathType: Prefix
EOF
```

The command above creates an `Ingress` with host name `talker-api.127.0.0.1.nip.io`. If you are using a local Kubernetes cluster created with Kind, forward requests from your local port 8443 to the Envoy service running inside the cluster:

```sh
kubectl port-forward deployment/envoy 8443:8443 2>&1 >/dev/null &
```

## ❻ Create the `AuthConfig`

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

## ❼ Consume the API

With a TLS certificate signed by the trusted CA:

```sh
openssl genrsa -out /tmp/aisha.key 4096
openssl req -new -subj "/CN=aisha/C=PK/L=Islamabad/O=ACME Inc./OU=Engineering" -key /tmp/aisha.key -out /tmp/aisha.csr
openssl x509 -req -sha512 -days 1 -CA /tmp/ca.crt -CAkey /tmp/ca.key -CAcreateserial -extfile /tmp/x509v3.ext -in /tmp/aisha.csr -out /tmp/aisha.crt

curl -k --cert /tmp/aisha.crt --key /tmp/aisha.key https://talker-api.127.0.0.1.nip.io:8443 -i
# HTTP/1.1 200 OK
```

With a TLS certificate signed by the trusted CA, though missing an authorized Organization:

```sh
openssl genrsa -out /tmp/john.key 4096
openssl req -new -subj "/CN=john/C=UK/L=London" -key /tmp/john.key -out /tmp/john.csr
openssl x509 -req -sha512 -days 1 -CA /tmp/ca.crt -CAkey /tmp/ca.key -CAcreateserial -extfile /tmp/x509v3.ext -in /tmp/john.csr -out /tmp/john.crt

curl -k --cert /tmp/john.crt --key /tmp/john.key https://talker-api.127.0.0.1.nip.io:8443 -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Unauthorized
```

## ❽ Try the AuthConfig via raw HTTP authorization interface

Expose Authorino's raw HTTP authorization to the local host:

```sh
kubectl port-forward service/authorino-authorino-authorization 5001:5001 2>&1 >/dev/null &
```

With a TLS certificate signed by the trusted CA:

```sh
curl -k --cert /tmp/aisha.crt --key /tmp/aisha.key -H 'Content-Type: application/json' -d '{}' https://talker-api.127.0.0.1.nip.io:5001/check -i
# HTTP/2 200
```

With a TLS certificate signed by an unknown authority:

```sh
openssl req -x509 -sha512 -nodes \
  -days 365 \
  -newkey rsa:4096 \
  -subj "/CN=untrusted" \
  -addext basicConstraints=CA:TRUE \
  -addext keyUsage=digitalSignature,keyCertSign \
  -keyout /tmp/untrusted-ca.key \
  -out /tmp/untrusted-ca.crt

openssl genrsa -out /tmp/niko.key 4096
openssl req -new -subj "/CN=niko/C=JP/L=Osaka" -key /tmp/niko.key -out /tmp/niko.csr
openssl x509 -req -sha512 -days 1 -CA /tmp/untrusted-ca.crt -CAkey /tmp/untrusted-ca.key -CAcreateserial -extfile /tmp/x509v3.ext -in /tmp/niko.csr -out /tmp/niko.crt

curl -k --cert /tmp/niko.crt --key /tmp/niko.key -H 'Content-Type: application/json' -d '{}' https://talker-api.127.0.0.1.nip.io:5001/check -i
# HTTP/2 401
# www-authenticate: Basic realm="mtls"
# x-ext-auth-reason: x509: certificate signed by unknown authority
```

## ❾ Revoke an entire chain of certificates

```sh
kubectl delete secret/talker-api-ca
```

Even if the deleted root certificate is still cached and accepted at the gateway, Authorino will revoke access at application level immediately.

Try with a previously accepted certificate:

```sh
curl -k --cert /tmp/aisha.crt --key /tmp/aisha.key https://talker-api.127.0.0.1.nip.io:8443 -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Basic realm="mtls"
# x-ext-auth-reason: x509: certificate signed by unknown authority
```

## Cleanup

```sh
kind delete cluster --name authorino-tutorial
```
