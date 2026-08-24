# User guide: Limiting network traffic to Authorino

Use Kubernetes [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) resources to restrict ingress traffic to Authorino pods, ensuring only production-facing endpoints are reachable and diagnostic or debug ports are blocked.

> [!WARNING]
> NetworkPolicies require a CNI plugin that supports them (for example, Calico, Cilium, Antrea). Clusters using a CNI without NetworkPolicy support (for example, vanilla Flannel) will accept the resources but not enforce them. Verify with your cluster administrator that NetworkPolicy enforcement is active.

## Authorino ports

Authorino listens on the following ports by default:

| Port  | Service                              | Flag / env var                                  | Production |
|-------|--------------------------------------|-------------------------------------------------|:----------:|
| 50051 | gRPC external authorization          | `--ext-auth-grpc-port` / `EXT_AUTH_GRPC_PORT`   | Yes        |
| 5001  | HTTP external authorization          | `--ext-auth-http-port` / `EXT_AUTH_HTTP_PORT`    | Yes        |
| 8083  | OIDC Discovery (Festival Wristbands) | `--oidc-http-port` / `OIDC_HTTP_PORT`            | Yes        |
| 8080  | Metrics (Prometheus)                 | `--metrics-addr`                                | Yes        |
| 8081  | Health/readiness probes              | `--health-probe-addr`                           | Yes        |
| 9443  | Admission webhooks                   | `--webhook-service-port`                        | Yes        |
| 8084  | pprof debug endpoint                 | `--pprof-bind-address`                          | No         |

Ports marked as non-production should not be reachable in production environments. The NetworkPolicy below allows ingress only on the production ports, implicitly blocking all others.

## Applying the NetworkPolicy

The following NetworkPolicy allows ingress only on the production Authorino ports, implicitly blocking debug/diagnostic endpoints and any other unlisted port.

Before applying, verify the labels on your Authorino pods:

```sh
kubectl get pods -n <authorino-namespace> -l authorino-resource --show-labels
```

The `authorino-resource` label is set by the [Authorino Operator](https://github.com/kuadrant/authorino-operator) to the name of the `Authorino` custom resource. Adjust the `podSelector` below to match.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: authorino-allow-ingress
  namespace: authorino # (1)
spec:
  podSelector:
    matchLabels:
      authorino-resource: authorino # (2)
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - port: 50051
          protocol: TCP
        - port: 5001
          protocol: TCP
        - port: 8083
          protocol: TCP
        - port: 8080
          protocol: TCP
        - port: 8081
          protocol: TCP
        - port: 9443
          protocol: TCP
```

1. Replace with the namespace where Authorino is deployed.
2. Replace `authorino` with the name of your `Authorino` CR. Run `kubectl get authorinos -n <namespace>` to find it.

Apply with:

```sh
kubectl apply -f authorino-networkpolicy.yaml
```

### Verifying the policy

After applying, verify that non-production ports are blocked while production endpoints remain accessible.

Get the IP of one of the Authorino pods, using the same label selector as the NetworkPolicy:

```sh
export POD_IP=$(kubectl get pods -n <authorino-namespace> -l authorino-resource=authorino -o jsonpath='{.items[0].status.podIP}')
```

Then, from a pod in the same namespace:

```sh
# Should succeed (production port: health probe):
kubectl run -n <authorino-namespace> curl-test --rm -i --restart=Never --image=curlimages/curl -- \
  curl -s -o /dev/null -w "%{http_code}" http://$POD_IP:8081/healthz

# Should time out or be refused (non-production port: debug endpoint):
kubectl run -n <authorino-namespace> curl-test --rm -i --restart=Never --image=curlimages/curl -- \
  curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" http://$POD_IP:8084/debug/pprof/
```

### Omitting unused ports

If your deployment disables certain Authorino interfaces (for example, by setting `--ext-auth-http-port=0` or `--oidc-http-port=0`), you can remove the corresponding port from the `ingress` list in the NetworkPolicy to further reduce the attack surface:

```yaml
  ingress:
    - ports:
        - port: 50051   # remove if gRPC ext-auth is disabled
          protocol: TCP
        - port: 5001    # remove if HTTP ext-auth is disabled
          protocol: TCP
        - port: 8083    # remove if OIDC server is disabled
          protocol: TCP
        - port: 8080    # remove if metrics are not needed
          protocol: TCP
        - port: 8081    # keep — required for Kubernetes liveness/readiness probes
          protocol: TCP
        - port: 9443    # remove if admission webhooks are not used
          protocol: TCP
```

### Further restricting by source

The NetworkPolicy above allows ingress from **any** source on the listed ports. For defense-in-depth, you can restrict each port to specific source namespaces or pods. For example, to allow gRPC ext-auth only from the gateway namespace and metrics only from the monitoring namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: authorino-allow-ingress
  namespace: authorino
spec:
  podSelector:
    matchLabels:
      authorino-resource: authorino
  policyTypes:
    - Ingress
  ingress:
    # External authorization — from the gateway namespace only
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: gateway-namespace
      ports:
        - port: 50051
          protocol: TCP
        - port: 5001
          protocol: TCP
    # OIDC Discovery — from all sources
    - ports:
        - port: 8083
          protocol: TCP
    # Metrics — from monitoring namespace only
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 8080
          protocol: TCP
    # Health probes — from all sources (kubelet does not come from a pod)
    - ports:
        - port: 8081
          protocol: TCP
    # Webhooks — from all sources (API server)
    - ports:
        - port: 9443
          protocol: TCP
```
