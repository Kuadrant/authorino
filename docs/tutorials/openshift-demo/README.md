# Tutorial: Authorino on OpenShift

- [Intro](#intro)
- [Stack](#stack)
- [Deploy](#deploy)
- [Protect the API](#protect-the-api)
  - [Protect the API with Kubernetes auth tokens](#protect-the-api-with-kubernetes-auth-tokens)
  - [Protect the API with API Key](#protect-the-api-with-api-key)
  - [Restrict access to endpoints of the API with JSON authorization policies](#restrict-access-to-endpoints-of-the-api-with-json-authorization-policies)
- [Cleanup](#cleanup)
- [Extras](#extras)
  - [Review a Kubernetes token](#review-a-kubernetes-token)

## Intro

This tutorial will walk you through the steps of deploying Authorino and the Envoy proxy to a running instance of an OpenShft server, and use it to protect a sample API with 2 authentication methods (Kubernetes tokens and API keys) and authorization policies that restrict access to certain endpoints of the API according to the identity source.

The following Authorino features are covered in this tutorial:
- Kubernetes auth
- API key auth
- JSON authorization policies

## Stack

The following applications compose the stack for this tutorial:

- **Talker API**<br/>
    Just a simple rack application that echoes back in a JSON whatever it gets in the request.
- **Envoy proxy**<br/>
    Serving the Talker API, configured with the ext_authz http filter pointing to Authorino.
- **Authorino**<br/>
    The AuthN/AuthZ enforcer that will watch and apply Authorino `AuthConfig` custom resources in the Kubernetes/OpenShift server.

## Deploy

Follow the instructions below to deploy the stack of resources and applications to a running instance of an OpenShift server.

> **NOTE:** Except for a few OpenShift-specific parts, the rest of the tutorial should work without issues on bare Kubernetes. Examples of OpenShift-specific parts and how to adapt them for bare Kubernetes:
> - Use of `oc` in some commands → replace accordingly with `kubectl`
> - Use of OpenShift `Route` resource to expose the Envoy service → replace accondingly with an `Ingress` resource

#### Instructions

1. Obtain an access token to the target OpenShift cluster:

    You can obtain an access token to an OpenShift cluster via OpenShift web console or, if you are logged in with the CLI, by reading the token from the `.kube/conf` file:

    ```sh
    $ yq r ~/.kube/config "users(name==$(yq r ~/.kube/config 'current-context' | awk -F "/" '{ print $3"/"$2 }')).user.token"
    ```

2. Set the envs replacing the values accordingly:

    ```sh
    $ export OPENSHIFT_TOKEN=my-openshift-access-token \
             AUTHORINO_NAMESPACE=authorino-demo \
             TALKER_API_HOST=talker-api.apps.my-openshift-server
    ```

3. Create the OpenShift project:

    ```sh
    $ oc new-project $AUTHORINO_NAMESPACE
    ```

4. Download the required resources:

    ```sh
    $ git clone https://gist.github.com/4a86682282994ac5f9bb1f246f19df39.git authorino-openshift && cd authorino-openshift
    ```

5. Patch the resources replacing the parameters to your env values:

   ```sh
   $ sed -i -e "s/\${AUTHORINO_NAMESPACE}/$AUTHORINO_NAMESPACE/g;s/\${TALKER_API_HOST}/$(print $TALKER_API_HOST | sed -e 's/\./\\\./g')/g" *.yaml
   ```

6. Deploy Authorino:

    ```sh
    $ kubectl apply -f authorino.yaml
    customresourcedefinition.apiextensions.k8s.io/authconfigs.authorino.3scale.net created
    role.rbac.authorization.k8s.io/authorino-leader-election-role created
    clusterrole.rbac.authorization.k8s.io/authorino-manager-role created
    clusterrole.rbac.authorization.k8s.io/authorino-metrics-reader created
    clusterrole.rbac.authorization.k8s.io/authorino-proxy-role created
    rolebinding.rbac.authorization.k8s.io/authorino-leader-election-rolebinding created
    clusterrolebinding.rbac.authorization.k8s.io/authorino-manager-rolebinding created
    clusterrolebinding.rbac.authorization.k8s.io/authorino-proxy-rolebinding created
    service/authorino-authorization created
    service/authorino-controller-manager-metrics-service created
    deployment.apps/authorino-controller-manager created
    ```

7. Deploy the Talker API:

    ```sh
    $ kubectl apply -f talker-api-deploy.yaml
    deployment.apps/talker-api created
    service/talker-api created
    ```

8. Deploy the Envoy proxy:

    ```sh
    $ kubectl apply -f envoy-deploy.yaml
    deployment.apps/envoy created
    service/envoy created
    route.route.openshift.io/talker-api created
    configmap/envoy created
    ```

## Protect the API

### Protect the API with Kubernetes auth tokens

Apply the CR:

```yaml
# talker-api-protection-1.yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
    - talker-api.apps.my-openshift-server
  identity:
    - name: dev-eng-ocp45-users
      kubernetes:
        audiences:
          - https://kubernetes.default.svc # default audience of K8s tokens - change accordingly for less permissive scope
```

```sh
$ kubectl apply -f talker-api-protection-1.yaml
route.route.openshift.io/talker-api created
```

Send requests to the API:

```sh
$ curl -k -H "Authorization: Bearer $OPENSHIFT_TOKEN" https://$TALKER_API_HOST/hello
200 OK

$ curl -k -H "Authorization: Bearer nonono" https://$TALKER_API_HOST/hello
401 Unauthorized
```

### Protect the API with API Key

Apply the CR:

```yaml
# talker-api-protection-2.yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
    - talker-api.apps.my-openshift-server
  identity:
    - name: dev-eng-ocp45-users
      kubernetes: {…}
    - name: external-access
      apiKey:
        labelSelectors:
          authorino.3scale.net/managed-by: authorino
          scope: talker-api
      credentials:
        in: authorization_header
        keySelector: APIKEY

```

```sh
$ kubectl apply -f talker-api-protection-2.yaml
service.authorino.3scale.net/talker-api-protection configured
```

Create an API key:

```sh
$ kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: talker-api-api-key-1
  labels:
    authorino.3scale.net/managed-by: authorino
    scope: talker-api
  annotations:
    user/username: friend
    user/email: friend@example.com
stringData:
  api_key: $(openssl rand -hex 32)
type: Opaque
EOF
secret/talker-api-api-key-1 created

$ export API_KEY=$(kubectl get secret/talker-api-api-key-1 -o json | jq -r '.data.api_key' | base64 -d)
```

Send requests to the API:

```sh
$ curl -k -H "Authorization: APIKEY $API_KEY" https://$TALKER_API_HOST/hello
# 200 OK

$ curl -k -H "Authorization: APIKEY nonono" https://$TALKER_API_HOST/hello
# 401 Unauthorized
```

### Restrict access to endpoints of the API with JSON authorization policies

Apply the CR:

```yaml
# talker-api-protection-3.yaml
apiVersion: authorino.3scale.net/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
    - talker-api.apps.my-openshift-server
  identity: {…}
  authorization:
    - name: only-developers
      json:
        conditions:
          - selector: context.request.http.path
            operator: eq
            value: /only-developers
        rules:
          - selector: auth.identity.groups
            operator: incl
            value: developer
    - name: only-externals
      json:
        conditions:
          - selector: context.request.http.path
            operator: eq
            value: /only-externals
        rules:
          - selector: auth.identity.metadata.annotations.user/email
            operator: matches
            value: "\\w+@example.com$"
```

```sh
$ kubectl apply -f talker-api-protection-3.yaml
service.authorino.3scale.net/talker-api-protection configured
```

Send requests to the API with the OpenShift access token:

```sh
$ curl -k -H "Authorization: Bearer $OPENSHIFT_TOKEN" https://$TALKER_API_HOST/hello
200 OK

$ curl -k -H "Authorization: Bearer $OPENSHIFT_TOKEN" https://$TALKER_API_HOST/only-developers
200 OK

$ curl -k -H "Authorization: Bearer $OPENSHIFT_TOKEN" https://$TALKER_API_HOST/only-externals
403 Forbidden
```

Send requests to the API with the API key:

```sh
$ curl -k -H "Authorization: APIKEY $API_KEY" https://$TALKER_API_HOST/hello
200 OK

$ curl -k -H "Authorization: APIKEY $API_KEY" https://$TALKER_API_HOST/only-developers
403 Forbidden

$ curl -k -H "Authorization: APIKEY $API_KEY" https://$TALKER_API_HOST/only-externals
200 OK
```

## Cleanup

```sh
$ kubectl delete -f authorino.yaml
customresourcedefinition.apiextensions.k8s.io "authconfigs.authorino.3scale.net" deleted
role.rbac.authorization.k8s.io "authorino-leader-election-role" deleted
clusterrole.rbac.authorization.k8s.io "authorino-manager-role" deleted
clusterrole.rbac.authorization.k8s.io "authorino-metrics-reader" deleted
clusterrole.rbac.authorization.k8s.io "authorino-proxy-role" deleted
rolebinding.rbac.authorization.k8s.io "authorino-leader-election-rolebinding" deleted
clusterrolebinding.rbac.authorization.k8s.io "authorino-manager-rolebinding" deleted
clusterrolebinding.rbac.authorization.k8s.io "authorino-proxy-rolebinding" deleted
service "authorino-authorization" deleted
service "authorino-controller-manager-metrics-service" deleted
deployment.apps "authorino-controller-manager" deleted

$ oc delete project $AUTHORINO_NAMESPACE
project.project.openshift.io "authorino-demo" deleted
```

## Extras

### Review a Kubernetes token

```sh
$ kubectl create -o yaml -f -<<EOF
apiVersion: authentication.k8s.io/v1
kind: TokenReview
spec:
  token: $OPENSHIFT_TOKEN
EOF
```

Example output for a token issued in OpenShift:

```yaml
apiVersion: authentication.k8s.io/v1
kind: TokenReview
metadata:
  creationTimestamp: null
  managedFields:
  - apiVersion: authentication.k8s.io/v1
    fieldsType: FieldsV1
    fieldsV1:
      f:spec:
        f:token: {}
    manager: kubectl-create
    operation: Update
    time: "2021-04-15T09:22:13Z"
spec:
  token: -REDACTED-
status:
  audiences:
  - https://kubernetes.default.svc
  authenticated: true
  user:
    extra:
      scopes.authorization.openshift.io:
      - user:full
    groups:
    - developer
    - system:authenticated:oauth
    - system:authenticated
    uid: da10c029-0e55-44fc-9c9e-9f04398ed5b3
    username: john
```
