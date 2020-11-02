# Proofs of Concept

These are other Proof-of-Concept (PoCs) implementations tried within the scope of 3scale AuthN/AuthZ initiative.

### Hosted PoCs

**Keycloak Ruby Adapter** · [ruby-keycloak-authz](ruby-keycloak-authz)<br/>
Sample Ruby On Rails app with an OIDC adapter for identity verification and authorization with Keycloak/Red Hat SSO.

**Envoy ext_authz + OPA** · [envoy-opa-authz](envoy-opa-authz)<br/>
Authentication (OIDC) and authorization with OPA, invoked directly with Envoy ext_authz filter.

### External PoCs

**Ostia external authorization** · https://github.com/3scale/ostia/pull/76<br/>
The embryo of Authorino as proposed for the 3scale Ostia architecture.

**Portafly + Keycloak** · https://github.com/didierofrivia/portafly<br/>
Demo: using Keycloak to authenticate and authorize requests between a SPA and a node.js resource server.

**Envoy JWT plugin** · https://github.com/3scale/gateway-ng-controller/pull/28<br/>
Envoy proxy extension to implement plug-in OIDC-based authentication with JSON Web Tokens (JWT).
