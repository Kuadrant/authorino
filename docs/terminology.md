# Terminology
Here we define some terms that are used in the project, with the goal of avoiding confusion and facilitating more
accurate conversations related to `Authorino`.

If you see terms used that are not here (or are used in place of terms here) please considre contributing a definition
to this doc with a PR, or modifying the use elsewhere to align with these terms.

## Terms
* **Access token**: a type of temporary security token, tied to an authenticated identity, that is issued by an auth 
  server under request of registered auth clients of this auth server, and that delegates power of operating on 
  behalf of that identity to a party that presents this token on requests to a resource server, including and 
  especially to the auth client itself; it is typically formatted as a JWT
* **Auth**: usually employed as a short for authentication and authorization (AuthN/AuthZ)
* **Auth client**: an application client that uses an auth server, either to authenticate or to authorize identities 
  who want to consume resources from a resources server; it can represent a user application like a SPA or a mobile 
  app, or a resource server
* **Auth server**: a server where auth clients, users, roles, scopes, resources, policies and permissions are stored and 
  managed
* **Authentication (AuthN)**: the process of verifying that a given credential belongs to a claimed-to-be identity; 
  usually resulting in the issuing of an access token
* **Authorization (AuthZ)**: the process of grating (or denied) access over a resource to a party based on the set of 
  policies and permissions enforced and
* **Capability**: usually employed to refer to a management feature of a cloud-native system, based on the definition 
  and use of Kubernetes custom resources (CRDs and CRs), that enables that system to one of the following 
  “capability levels”: Basic Install, Seamless Upgrades, Full Lifecycle, Deep Insights, Auto Pilot
* **Claim**: an attribute packaged in a security token which represents a claim that the provider of the token is making 
  about an entity
* **Client ID**:
* **Client secret**:
* **Identity**:
* **Identity Provider (IdP)**:
* **ID token**:
* **JSON Web Token (JWT)**:
* **Keycloak**: open source auth server to allow single sign-on with identity and access management.
* **Lightweight Directory Access Protocol (LDAP)**: open standard for distributed directory information services for 
  sharing of information about users, systems, networks, services and applications.
* **Mutual Transport Layer Security (mTLS)**: protocol for the mutual authentication of client-server communication, 
  i.e., the client authenticates the server and the server authenticates the client, based on the acceptance of 
  the X.509 certificates of each party.
* **OAuth2**:
* **OpenID Connect (OIDC)**:
* **Open Policy Agent (OPA)**:
* **Party Token (RPT)**:
* **Permission**:
* **Policy**:
* **Policy Administration Point (PAP)**: set of UIs and APIs to manage resources servers, resources, scopes, policies 
  and permissions; it is where the auth system is configured.
* **Policy Decision Point (PDP)**: where the authorization requests are sent and policies are evaluated accordingly with 
  the permissions being requested.
* **Policy Enforcement Point (PEP)**: where the authorization is effectively enforced, usually at the resource server side, 
  based on a response provided by the Policy Decision Point (PDP).
* **Policy Storage**: where policies are stored and from where they can be fetched, perhaps to be cached.
* **Red Hat SSO**: auth server; downstream version of Keycloak.
* **Refresh token**:
* **Resource**:
* **Resource server**:
* **Role**: an aspect of a user’s identity assigned to the user to indicate the level of access they should have to the 
  system; essentially, roles represent collections of permissions
* **Scope**: a mechanism that defines the specific operations applications can be allowed to do or information that they 
  can request on an identity’s behalf. When an app requests permission to access a resource through an auth server, 
  it uses the scope parameter to specify what access it needs, and the auth server uses the scope parameter to respond 
  with the access that was actually granted.
* **Single Page Application (SPA)**:
* **Single Sign-on (SSO)**:
* **User-Managed-Access (UMA)**: