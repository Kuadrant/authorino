# Deploying Authorino

1. [Clone the repo](#clone-the-repo)
2. [Meet the requirements](#meet-the-requirements)
3. [Deploy](#deploy)
   - [Option A: Local cluster](#option-a-local-cluster)
   - [Option B: Custom deployment](#option-b-custom-deployment)

## Clone the repo

This is the easiest way to get Authorino's Kubernetes resources and deployment utils.

```sh
git clone git@github.com:3scale-labs/authorino.git && cd authorino
```

## Meet the requirements

Having a [Kubernetes](https://kubernetes.io/) server up and running is the only actual requirement to deploy Authorino.

With the tools provided in the Authorino repo nevertheless, you can easily have a local cluster setup (using [Kind](https://kind.sigs.k8s.io)). In this case, the only requirement is [Docker](https://docker.com).

Apart from the obvious requirement of having a running instance of a Kubernetes server, Authorino also relies on some other components and capabilities to perform its function:

<!-- TODO: Add minimum required Kubernetes version -->

- Permission from the Kubernetes server to create Custom Resource Definitions (CRDs) during Authorino's installation. Cluster administrators can handle this requirement through the Kubernetes API Role-Based Access Control bindings.
- [Envoy](https://www.envoyproxy.io) proxy (or, technically, any proxy that implements the client-side of the [gRPC protocol](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz)). With Envoy, ultimately, virtual hosts will be associated to the upstream APIs to protect, and the [external authorization filter](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) should point to Authorino. Check [this example](/examples/envoy/envoy-deploy.yaml) if you need to.

### Feature-specific requirements

Some other feature-specific requirements (as opposed to actual requirements of Authorino) include:
- For OpenID Connect, make sure you have access to an identity provider (IdP) and an authority that can issue ID tokens (JWTs). You may want to check out [Keycloak](https://www.keycloak.org) which can solve both and connect to external identity sources and user federation like LDAP.
- For UMA-protected resource data, you will need a UMA-compliant server running as well. This can be an implementation of the UMA protocol by each upstream API itself or (more tipically) an external server that knows about the resources. Again, Keycloak can be a good fit here as well. Just keep in mind that, whatever resource server you choose, changing-state actions commanded in the upstream APIs or other parties will have to be reflected in the resource server. Authorino will not do that for you.
- For Kubernetes authentication tokens, in case you want to be able to requests access tokens for clients running outside the custer, you may want to check out the requisites for using Kubernetes [TokenRquest API](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#tokenrequest-v1-storage-k8s-io) (GA in v1.20).

## Deploy

Choose between the options below to continue:

[**Option A:** Local cluster (try it out and examples)](#option-a-local-cluster)<br/>
[**Option B:** Custom deployment](#option-b-custom-deployment)

### Option A: Local cluster

Option A is meant for trying out Authorino locally. It gives you a bundle of a [Kind](https://kind.sigs.k8s.io)-managed Kubernetes cluster, with a freshly built Authorino image and pre-configured sample resources.

Included resources:<br/>
- **Talker API**<br/>
    Just a simple rack application that echoes back in a JSON whatever it gets in the request. You can control the response by passing the custom HTTP headers X-Echo-Status and X-Echo-Message (both optional).
- **Authorino**<br/>
    The Cloud-native AuthN/AuthZ enforcer that looks for `config.authorino.3scale.net/Service` custom resources in the Kubernetes server to add protection to your APIs.
- **Envoy proxy**<br/>
    Serving requests to the Talker API virtual host and configured with the ext_authz http filter pointing to the Authorino service.

To start the local Kubernetes cluster, build and deploy Authorino, run:

```sh
make local-setup
```

You will then need to forward local requests to port 8000 to Envoy, by running:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
```

Check out below the other options to start the local environment adding either [Keycloak](https://www.keycloak.org) or [Dex](https://dexidp.io) IAM servers to the bundle.

#### Deploy with Keycloak

The [Keycloak](https://www.keycloak.org) bundle included can be used to issue OIDC tokens for providing resource data for the authorization policies.

The bundle comes preloaded with the following sample configs:<br/>
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

```sh
DEPLOY_KEYCLOAK=1 make local-setup
```

Forward local requests to the services running in the cluster, by running:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
kubectl -n authorino port-forward deployment/keycloak 8080:8080 &
```

#### Deploy with Dex

The [Dex](https://dexidp.io) bundle included is a simple OIDC identity provider server containing the following sample resources preloaded:<br/>
- Preloaded clients:<br/>
  - **demo**: to which API consumers delegate access and therefore the one which access tokens are issued to (Client secret: aaf88e0e-d41d-4325-a068-57c4b0d61d8e)
- Preloaded users:<br/>
  - marta@localhost/password

```sh
DEPLOY_DEX=1 make local-setup
```

Forward local requests to the services running in the cluster, by running:

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
kubectl -n authorino port-forward deployment/dex 5556:5556 &
```

#### Deploy with Keycloak and Dex

```sh
DEPLOY_IDPS=1 make local-setup
```

```sh
kubectl -n authorino port-forward deployment/envoy 8000:8000 &
kubectl -n authorino port-forward deployment/keycloak 8080:8080 &
kubectl -n authorino port-forward deployment/dex 5556:5556 &
```

#### Clean up

Delete the local Kind-managed Kubernetes cluster, thus cleaning up all resources deployed:

```sh
make local-cluster-down
```

### Option B: Custom deployment

A typical Authorino deployment to a Kubernetes server of choice includes:<br/>
- i. Authorino (CRD, some Roles and RoleBindings, Deployment and Service)
- ii. Envoy proxy (w/ ext_authz filter pointing to Authorino)
- iii. One or more APIs (upstreams) to be protected
- iv. Identity/authorization server (e.g. Keycloak), depending on the authentication methods chosen

The next steps provide some guidance on how to deploy Authorino, which is item (i) of the list of components above. To deploy and configure Envoy, as well as any possibly required identity providers/authorization servers, please refer to the corresponding docs of each of those components.

The [examples](/examples) provided in the Authorino repo may as well offer some hints on how to finish the deployment.

#### Choose your server

In case you do not have a target Kubernetes server where to deploy Authorino yet and simply want to try it out locally, you can launch a local cluster with [Kind](https://kind.sigs.k8s.io) by running:

```sh
make local-cluster-up
```

By defult, the new local cluster name will be "authorino". You can set a different one by changing Kind's context cluster name (environment variable `KIND_CLUSTER_NAME`).

#### Choose an image

By default, Authorino image tag will be assumed to be `authorino:latest`. You can check out [quay.io/3scale/authorino](https://quay.io/3scale/authorino) for an existing list of tags available, or build your own local image of Authorino.

To build you own local image based on the fetched version of the repo, run:

```sh
make docker-build
```

You can also set the environment variable `IMG` to control the name of tag. E.g.:

```sh
IMG=authorino:local make docker-build
```

The `IMG` parameter can be supplied as well as to the `local-push` and `deploy` targets mentioned below.

To push the Authorino image to a local Kubernetes cluster started with Kind, run:

```sh
make local-push
```

Use normal `docker push` command alternatively, i.e., in case you are not working with a local Kubernetes server started with the `local-cluster` make target but yet has built your own local image of Authorino.

#### Create the namespace

Export and create the Authorino namespace in the cluster:

```sh
export AUTHORINO_NAMESPACE="authorino"
kubectl create namespace "${AUTHORINO_NAMESPACE}"
kubectl config set-context --current --namespace="${AUTHORINO_NAMESPACE}"
```

#### Deploy Authorino

To create Authorino Custom Resource Definition (CRD), required Kubernetes Roles and RoleBindings, as well as Authorino's Deployment and Service, run:

```sh
make deploy
```

or, to specify a custom image:

```sh
IMG=authorino:custom-target make deploy
```

> **NOTE:** In case you are working with a local Kubernetes cluster started with Kind, have built and pushed a local image to the server registry, remind of Kubernetes default pull policy, which establishes that the image tag `:latest` causes the policy `Always` to be enforced. In such case, you may want to change the policy to `IfNotPresent`. See [Kubernetes `imagePullPolicy`](https://kubernetes.io/docs/concepts/containers/images/#updating-images) for more information.

#### Next steps

Finish the setup by deploying Envoy, upstream APIs to be protected with Authorino and possibly any required identity providers and authentication servers. You will then be ready to start creating `config.authorino.3scale.net/Service` custom resources representing the authN/authZ protection configs for your APIs.

Please check out as well the provided [examples](/examples) for more details about what can be done and the possible next steps to protect your APIs.
