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
- [Reach out](#reach-out)

## Technology stack for developers

Minimum requirements to contribute to Authorino are:
- [Golang v1.20+](https://golang.org)
- [Docker](https://docker.com)

Authorino's code was originally bundled using the [Operator SDK](https://sdk.operatorframework.io/) (v1.9.0).

The following tools can be installed as part of the development workflow:

- _Installed with `go install` to the `$PROJECT_DIR/bin` directory:_
  - [controller-gen](https://book.kubebuilder.io/reference/controller-gen.html): for building custom types and manifests
  - [Kustomize](https://kustomize.io/): for assembling flavoured manifests and installing/deploying
  - [setup-envtest](https://v0-19-x.sdk.operatorframework.io/docs/golang/references/env-test-setup): for running the tests – extra tools installed to `./testbin`
  - [benchstat]https://cs.opensource.google/go/x/perf): for human-friendly test benchmark reports
  - [mockgen](https://github.com/golang/mock/mockgen): to generate mocks for tests – e.g. `./bin/mockgen -source=pkg/auth/auth.go -destination=pkg/auth/mocks/mock_auth.go`
  - [Kind](https://kind.sigs.k8s.io): for deploying a containerized Kubernetes cluster for integration testing purposes

- _Other recommended tools to have installed:_
  - [jq](https://stedolan.github.io/jq/)
  - [yq](http://mikefarah.github.io/yq/)
  - [gnu-sed](https://www.gnu.org/software/sed/)

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

For additional automation provided, check:

```sh
make help
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
- Install [cert-manager](https://github.com/jetstack/cert-manager) in the cluster
- Install the [Authorino Operator](https://github.com/kuadrant/authorino-operator) and Authorino CRDs
- Build an image of Authorino based on the current branch
- Push the freshly built image to the cluster's registry
- Generate TLS certificates for the Authorino service
- Deploy an instance of Authorino
- Deploy the example application [**Talker API**](https://github.com/kuadrant/authorino-examples#talker-api), a simple HTTP API that echoes back whatever it gets in the request
- Setup Envoy for proxying to the Talker API and using Authorino for external authorization

```sh
make local-setup
```

You will be prompted to edit the `Authorino` custom resource.

The main workload composed of Authorino instance and user apps (Envoy, Talker API) will be deployed to the `default` Kubernetes namespace.

Once the deployment is ready, you can forward the requests on port 8000 to the Envoy service

```sh
kubectl port-forward deployment/envoy 8000:8000 &
```

<details>
  <summary>Pro tips</summary>

  1. Change the default workload namespace by supplying the `NAMESPACE` argument to your `make local-setup` and other deployment, apps and local cluster related targets. If the namespace does not exist, it will be created.
  2. Switch to TLS disabled by default when deploying locally by supplying `TLS_ENABLED=0` to your `make local-setup` and `make deploy` commands. E.g. `make local-setup TLS_ENABLED=0`.
  3. Skip being prompted to edit the `Authorino` CR and default to an Authorino deployment with TLS enabled, debug/development log level/mode, and standard name 'authorino', by supplying `FF=1` to your `make local-setup` and `make deploy` commands. E.g. `make local-setup FF=1`
  4. Supply `DEPLOY_IDPS=1` to `make local-setup` and `make user-apps` to deploy Keycloak and Dex to the cluster. `DEPLOY_KEYCLOAK` and `DEPLOY_DEX` are also available. Read more about additional tools for specific use cases in the section below.
  5. Saving the ID of the process (PID) of the port-forward command spawned in the background can be useful to later kill and restart the process. E.g. `kubectl port-forward deployment/envoy 8000:8000 &;PID=$!`; then `kill $PID`.
</details>

#### Additional tools (for specific use-cases)

<details>
  <summary><strong>Limitador</strong></summary>

  To deploy [Limitador](https://github.com/kuadrant/limitador) – pre-configured in Envoy for rate-limiting the Talker API to 5 hits per minute per `user_id` when available in the cluster workload –, run:

  ```sh
  kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/limitador/limitador-deploy.yaml
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
    - `/greetings/1` (owned by user john)
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
  kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/keycloak/keycloak-deploy.yaml
  ```

  Forward local requests to the instance of Keycloak running in the cluster:

  ```sh
  kubectl port-forward deployment/keycloak 8080:8080 &
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
  kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/dex/dex-deploy.yaml
  ```

  Forward local requests to the instance of Dex running in the cluster:

  ```sh
  kubectl port-forward deployment/dex 5556:5556 &
  ```
</details>

<details>
  <summary><strong>a12n-server</strong></summary>

  Authorino examples include a bundle of [**a12n-server**](https://github.com/curveball/a12n-server) and corresponding MySQL database, preloaded with the following setup:<br/>
  - Admin console: http://a12n-server:8531 (admin/123456)
  - Preloaded clients:<br/>
    - **service-account-1**: to obtain access tokens via `client_credentials` OAuth2 grant type, to consume the Talker API (Client secret: DbgXROi3uhWYCxNUq_U1ZXjGfLHOIM8X3C2bJLpeEdE); includes metadata privilege: `{ "talker-api": ["read"] }` that can be used to write authorization policies
    - **talker-api**: to authenticate to the token introspect endpoint (Client secret: V6g-2Eq2ALB1_WHAswzoeZofJ_e86RI4tdjClDDDb4g)

  To deploy, run:

  ```sh
  kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/a12n-server/a12n-server-deploy.yaml
  ```

  Forward local requests to the instance of a12n-server running in the cluster:

  ```sh
  kubectl port-forward deployment/a12n-server 8531:8531 &
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
1. Make sure you understand Authorino's [Logging](./user-guides/observability.md#logging) architecture and policy regarding log levels, log modes, tracing IDs, etc.
2. Respect controller-runtime's [Logging Guidelines](https://github.com/kubernetes-sigs/controller-runtime/blob/master/TMP-LOGGING.md).
3. Do not add sensitive data to your `info` log messages; instead, redact all sensitive data in your log messages or use `debug` log level by mutating the logger with `V(1)` before outputting the message.

## Additional resources

Here in the repo:

- [Getting started](./getting-started.md)
- [Terminology](./terminology.md)
- [Architecture](./architecture.md)
- [Feature description](./features.md)

Other repos:

- [Authorino Operator](https://github.com/kuadrant/authorino-operator)
- [Authorino examples](https://github.com/kuadrant/authorino-examples)

## Reach out

[#kuadrant](https://kubernetes.slack.com/archives/C05J0D0V525) channel on kubernetes.slack.com.
