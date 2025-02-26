# AuthConfig Consumers
Authorino's `AuthConfig` is a custom resource that defines authentication and authorization policies. Many tools and frameworks act
as consumers of `AuthConfig` by automatically generating and managing these resources on behalf of users. Since these consumers
follow the same specification, the general concepts and steps outlined in the user guides are applicable.
However, some details—such as resource names and specific API fields—may differ based on the consuming framework.

This section provides guidance for users working with tools that act as consumers of `AuthConfig`, allowing them to leverage the
same principles outlined in the user guides, regardless of the framework they are using.

## Kuadrant
[Kuadrant](https://kuadrant.io/) provides API security and access control capabilities through its own custom resource: `AuthPolicy`.
`AuthPolicy` is designed specifically for use with the Kubernetes [Gateway API](https://gateway-api.sigs.k8s.io/), allowing users
to define authentication and authorization rules directly in their network policy configurations.

Rather than defining `AuthConfig` resources directly, users can define an `AuthPolicy`, and Kuadrant will automatically
generate the corresponding `AuthConfig` for Authorino to consume.

Key details about `AuthPolicy` as an `AuthConfig` Consumer:

- **Same Specification**: The spec schema of `AuthPolicy` is effectively the same as `AuthConfig`.
- **Automatic Hostname Handling**: Unlike `AuthConfig`, `AuthPolicy` does not explicitly define `spec.host`. Instead, hostnames are
inferred from the Kubernetes network object in `spec.targetRef` and the route selectors in the policy.
- **Authorino Integration**: Kuadrant translates `AuthPolicy` into an `AuthConfig`, which is then processed by Authorino to enforce
authentication and authorization.

For more details on enforcing authentication and authorization with Kuadrant, see the
[Kuadrant Auth documentation](https://docs.kuadrant.io/latest/kuadrant-operator/doc/overviews/auth/).
