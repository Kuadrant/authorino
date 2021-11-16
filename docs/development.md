# Developer's Guide

- [Technology stack for developers](#technology-stack-for-developers)
- [Workflow](#workflow)
  - [Check the issues](#check-the-issues)
  - [Clone the repo and setup the local environment](#clone-the-repo-and-setup-the-local-environment)
  - [Make your changes](#make-your-changes)
  - [Run the tests](#run-the-tests)
  - [Try locally](#try-locally)
    - [Build, deploy and try Authorino in a local cluster](#build-deploy-and-try-authorino-in-a-local-cluster)
    - [Additional tools (for specific use-cases)](#additional-tools-for-specific-use-cases)
    - [Re-build and rollout latest](#re-build-and-rollout-latest)
    - [Clean-up](#clean-up)
  - [Sign your commits](#sign-your-commits)
- [Logging policy](#logging-policy)
- [Additional resources](#additional-resources)

## Technology stack for developers

Minimum requirements to contribute to Authorino are:
- [Golang v1.16+](https://golang.org)
- [Docker](https://docker.com)

Authorino's code was bundle using the [Operator SDK](https://sdk.operatorframework.io/) (v1.9.0).

The following tools will be installed as part of the development workflow:

- _Installed with `go get` to a temp directory:_
  - [controller-gen](https://book.kubebuilder.io/reference/controller-gen.html): for building custom types and manifests
  - [Kustomize](https://kustomize.io/): for assembling flavoured manifests and installing/deploying

- _Installed with `go install` to your `GOBIN` directory:_
  - [Kind](https://kind.sigs.k8s.io): for deploying a containerized Kubernetes cluster for integration testing purposes
  - [setup-envtest](https://v0-19-x.sdk.operatorframework.io/docs/golang/references/env-test-setup): for running the tests – extra tools installed to `./testbin`

- _Other recommended tools (for specific examples and debugging):_
  - [jq](https://stedolan.github.io/jq/)
  - [yq](http://mikefarah.github.io/yq/)

## Workflow

![Development workflow](http://www.plantuml.com/plantuml/png/LKz1QiGm3Bpx5MBlfJye2uNU2alR3nXNn26s5IJvaD_NKbBm7gBCQ0RD-2uQMNijGRQrxP5ZXKgDKcQg2CeTGs1C6jjI46xl6TC6cX5MaOvoWoWdd5qVnDjhAjJGhOmxkT40pCRFk24Sr1bI7glhteLdum-AkgO3F0byGA4KIpbEdOzP_bwNTWLGhQkU0JAsi-lH9NlJnvVh--0X-BFWvSrh1nj6_ijTVrjv9nj6hC3u37gC3ID-yuxjjzVo1m00)

### Check the issues
Start by checking the list of [issues](https://github.com/kuadrant/authorino/issues) in GitHub.

In case you want to contribute with an idea for enhancement, a bug fix, or question, please make sure to [describe the issue](https://github.com/kuadrant/authorino/issues/new) so we can start a conversation together and help you find the best way to get your contribution merged.

### Clone the repo and setup the local environment

Fork/clone the repo:

```sh
git clone git@github.com:kuadrant/authorino.git && cd authorino
```

Download the Golang dependencies:
```sh
make vendor
```

### Make your changes

Good changes...
- follow the [Golang conventions](https://golang.org/doc/effective_go)
- have proper test coverage
- address corresponding updates to the [docs](./)
- help us fix wherever we failed to do the above 😜

### Run the tests

To run the tests:

```sh
make test
```

### Try locally

#### Build, deploy and try Authorino in a local cluster

The following command will:
- Start a local Kubernetes cluster (using Kind)
- Install the [Authorino Operator](https://github.com/kuadrant/authorino-operator) and Authorino CRDs
- Build an image of Authorino based on the current branch
- Push the freshly built image to the cluster's registry
- Install [cert-manager](https://github.com/jetstack/cert-manager) in the cluster
- Create a namespace for you tests
- Install the example application [**Talker API**](../examples/talker-api/talker-api-deploy.yaml), a simple HTTP API that echoes back whatever it gets in the request
- Setup Envoy for proxying to the Talker API and using Authorino for external authorization

```sh
make local-setup
```

Create the `Authorino` custom resource, e.g.:

```sh
kubectl -n authorino apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  image: authorino:local
  replicas: 1
  clusterWide: false
  listener:
    tls:
      enabled: true
      certSecretRef:
        name: authorino-server-cert
  oidcServer:
    tls:
      enabled: true
      certSecretRef:
        name: authorino-oidc-server-cert
EOF
```

Once the deployment is ready, you can forward the requests on port 8000 to the Envoy service

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
```

You can skip the step of building a local image of Authorino based on the current branch and default to `quay.io/3scale/authorino:latest` instead by passing `SKIP_LOCAL_BUILD=1` to `make local-setup`.

#### Additional tools (for specific use-cases)

<details>
  <summary><strong>Limitador</strong></summary>

  To deploy [Limitador](https://github.com/kuadrant/limitador) – pre-configured in Envoy for rate-limiting the Talker API to 5 hits per minute per `user_id` when available in the cluster workload –, run:

  ```sh
  kubectl -n authorino apply -f examples/limitador/limitador-deploy.yaml
  ```
</details>

<details>
  <summary><strong>Keycloak</strong></summary>

  Authorino examples include a bundle of [Keycloak](https://www.keycloak.org) preloaded with the following realm setup:<br/>
  - Admin console: http://localhost:8080/auth/admin (admin/p)
  - Preloaded realm: **kuadrant**
  - Preloaded clients:
    - **demo**: to which API consumers delegate access and therefore the one which access tokens are issued to
    - **authorino**: used by Authorino to fetch additional user info with `client_credentials` grant type
    - **talker-api**: used by Authorino to fetch UMA-protected resource data associated with the Talker API
  - Preloaded resources:
    - `/hello`
    - `/greetings/1` (owned by user jonh)
    - `/greetings/2` (owned by user jane)
    - `/goodbye`
  - Realm roles:
    - member (default to all users)
    - admin
  - Preloaded users:
    - john/p (member)
    - jane/p (admin)
    - peter/p (member, email not verified)

  To deploy, run:

  ```sh
  kubectl -n authorino apply -f examples/keycloak/keycloak-deploy.yaml
  ```

  Forward local requests to the instance of Keycloak running in the cluster:

  ```sh
  kubectl -n authorino port-forward deployment/keycloak 8080:8080 &
  ```
</details>

<details>
  <summary><strong>Dex</strong></summary>

  Authorino examples include a bundle of [Dex](https://dexidp.io) preloaded with the following setup:<br/>
  - Preloaded clients:<br/>
    - **demo**: to which API consumers delegate access and therefore the one which access tokens are issued to (Client secret: aaf88e0e-d41d-4325-a068-57c4b0d61d8e)
  - Preloaded users:<br/>
    - marta@localhost/password

  To deploy, run:

  ```sh
  kubectl -n authorino apply -f examples/dex/dex-deploy.yaml
  ```

  Forward local requests to the instance of Dex running in the cluster:

  ```sh
  kubectl -n authorino port-forward deployment/dex 5556:5556 &
  ```
</details>

#### Re-build and rollout latest

Re-build and rollout latest Authorino image:

```sh
make local-rollout
```

If you made changes to the CRD between iterations, re-install by running:

```sh
make install
```

#### Clean-up

The following command deletes the entire Kubernetes cluster started with Kind:

```sh
make local-cleanup
```

### Sign your commits

All commits to be accepted to Authorino's code are required to be signed. Refer to [this page](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits) about signing your commits.

## Logging policy

A few guidelines for adding logging messages in your code:
1. Make sure you understand Authorino's [Logging](./logging.md) architecture and policy regarding log levels, log modes, tracing IDs, etc.
2. Respect controller-runtime's [Logging Guidelines](https://github.com/kubernetes-sigs/controller-runtime/blob/master/TMP-LOGGING.md).
3. Do not add sensitive data to your `info` log messages; instead, redact all sensitive data in your log messages or use `debug` log level by mutating the logger with `V(1)` before outputting the message.

## Additional resources

- [Getting started](./getting-started.md)
- [Terminology](./terminology.md)
- [Architecture](./architecture.md)
- [Feature description](./features.md)
