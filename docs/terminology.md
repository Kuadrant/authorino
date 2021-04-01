# Terminology
Here we define some terms that are used in the project, with the goal of avoiding confusion and facilitating more
accurate conversations related to `Authorino`.

If you see terms used that are not here (or are used in place of terms here) please consider contributing a definition
to this doc with a PR, or modifying the use elsewhere to align with these terms.

## Terms
**Access token**<br/>
Type of temporary password (security token), tied to an authenticated identity, issued by an auth server as of request from either the identity subject itself or a registered auth client known by the auth server, and that delegates to a party powers to operate on behalf of that identity before a resource server; it can be formatted  as an opaque data string or as an encoded JSON Web Token (JWT).


**Application Programming Interface (API)**<br/>
Interface that defines interactions between multiple software applications; _(in HTTP communication)_ set of endpoints and specification to expose resources hosted by a resource server, to be consumed by client applications; the access facade of a resource server.


**Attribute-based Access Control (ABAC)**<br/>
Authorization model that grants/denies access to resources based on evaluation of authorization policies which combine attributes together (from claims, from the request, from the resource, etc).


**Auth**<br/>
Usually employed as a short for authentication and authorization together (AuthN/AuthZ).


**Auth client**<br/>
Application client (software) that uses an auth server, either in the process of authenticating and/or authorizing identity subjects (including self) who want to consume resources from a resources server or auth server.


**Auth server**<br/>
Server where auth clients, users, roles, scopes, resources, policies and permissions can be stored and managed.


**Authentication (AuthN)**<br/>
Process of verifying that a given credential belongs to a claimed-to-be identity; usually resulting in the issuing of an access token.


**Authorization (AuthZ)**<br/>
Process of granting (or denying) access over a resource to a party based on the set of authorization rules, policies and/or permissions enforced.


**Authorization header**<br/>
HTTP request header frequently used to carry credentials to authenticate a user in an HTTP communication, like in requests sent to an API; alternatives usually include credentials carried in another (custom) HTTP header, query string parameter or HTTP cookie.


**Capability**<br/>
Usually employed to refer to a management feature of a cloud-native system, based on the definition and use of Kubernetes Custom Resources (CRDs and CRs), that enables that system to one of the following “capability levels”: Basic Install, Seamless Upgrades, Full Lifecycle, Deep Insights, Auto Pilot.


**Claim**<br/>
Attribute packed in a security token which represents a claim that one who bears the token is making about an entity, usually an identity subject.


**Client ID**<br/>
Unique identifier of an auth client within an auth server domain (or auth server realm).


**Client secret**<br/>
Password presented by auth clients together with their Client IDs while authenticating with an auth server, either when requesting access tokens to be issued or when consuming services from the auth servers in general.


**Delegation**<br/>
Process of granting a party (usually an auth client) with powers to act, often with limited scope, on behalf of an identity, to access resources from a resource server. See also _OAuth2_.


**Hash-based Message Authentication Code (HMAC)**<br/>
Specific type of message authentication code (MAC) that involves a cryptographic hash function and a shared secret cryptographic key; it can be used to verify the authenticity of a message and therefore as an authentication method.


**Identity**<br/>
Set of properties that qualifies a subject as a strong identifiable entity (usually a user), who can be authenticated by an auth server. See also _Claims_.


**Identity and Access Management (IAM) system**<br/>
Auth system that implements and/or connects with sources of identity (IdP) and offers interfaces for managing access (authorization policies and permissions). See also _Auth server_.


**Identity Provider (IdP)**<br/>
Source of identity; it can be a feature of an auth server or external source connected to an auth server.


**ID token**<br/>
Special type of access token; an encoded JSON Web Token (JWT) that packs claims about an identity.


**[JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)**<br/>
JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties.


**[JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)**<br/>
Standard for signing arbitrary data, especially JSON Web Tokens (JWT).


**JSON Web Key Set (JWKS)**<br/>
Set of keys containing the public keys used to verify any JSON Web Token (JWT).


**[Keycloak](https://www.keycloak.org)**<br/>
Open source auth server to allow single sign-on with identity and access management.


**Lightweight Directory Access Protocol (LDAP)**<br/>
Open standard for distributed directory information services for sharing of information about users, systems, networks, services and applications.


**Mutual Transport Layer Security (mTLS)**<br/>
Protocol for the mutual authentication of client-server communication, i.e., the client authenticates the server and the server authenticates the client, based on the acceptance of the X.509 certificates of each party.


**[OAuth 2.0 (OAuth2)](https://oauth.net/2)**<br/>
Industry-standard protocol for delegation.


**[OpenID Connect (OIDC)](https://openid.net/connect)**<br/>
Simple identity verification (authentication) layer built on top of the OAuth2 protocol.


**[Open Policy Agent (OPA)](https://www.openpolicyagent.org)**<br/>
Authorization policy agent that enables the usage of declarative authorization policies written in Rego language.


**Opaque token**<br/>
Security token devoid of explicit meaning (e.g. random string); it requires the usage of lookup mechanism to be translated into a meaningful set claims representing an identity.


**Permission**<br/>
Association between a protected resource the authorization policies that must be evaluated whether access should be granted; e.g. _`<user|group|role>` CAN DO `<action>` ON RESOURCE `<X>`_.


**Policy**<br/>
Rule or condition (authorization policy) that must be satisfied to grant access to a resource; strongly related to the different access control mechanisms (ACMs) and strategies one can use to protect resources, e.g. attribute-based access control (ABAC), role-based access control (RBAC), context-based access control, user-based access control (UBAC).


**Policy Administration Point (PAP)**<br/>
Set of UIs and APIs to manage resources servers, resources, scopes, policies and permissions; it is where the auth system is configured.


**Policy Decision Point (PDP)**<br/>
Where the authorization requests are sent, with permissions being requested, and authorization policies are evaluated accordingly.


**Policy Enforcement Point (PEP)**<br/>
Where the authorization is effectively enforced, usually at the resource server or at a proxy, based on a response provided by the Policy Decision Point (PDP).


**Policy storage**<br/>
Where policies are stored and from where they can be fetched, perhaps to be cached.


**Red Hat SSO**<br/>
Auth server; downstream product created from the Keycloak Open Source project.


**[Refresh token](https://tools.ietf.org/html/rfc6749#section-1.5)**<br/>
Special type of security token, often provided together with an access token in an OAuth2 flow, used to renew the duration of an access token before it expires; it requires client authentication.


**[Request Party Token (RPT)](https://www.keycloak.org/docs/5.0/authorization_services/#_service_rpt_overview)**<br/>
JSON Web Token (JWT) digitally signed using JSON Web Signature (JWS), issued by the Keycloak auth server.


**Resource**<br/>
One or more endpoints of a system, API or server, that can be protected.


**Resource-level Access Control (RLAC)**<br/>
Authorization model that takes into consideration attributes of each specific request resource to grant/deny access to those resources (e.g. the resource's owner).


**Resource server**<br/>
Server that hosts protected resources.


**Role**<br/>
Aspect of a user’s identity assigned to the user to indicate the level of access they should have to the system; essentially, roles represent collections of permissions


**Role-based Access Control (RBAC)**<br/>
Authorization model that grants/denies access to resources based on the roles of authenticated users (rather than on complex attributes/policy rules).


**Scope**<br/>
Mechanism that defines the specific operations that applications can be allowed to do or information that they can request on an identity’s behalf; often presented as a parameter when access is requested as a way to communicate what access is needed, and used by auth server to respond what actual access is granted.


**[Single Page Application (SPA)](https://en.wikipedia.org/wiki/Single-page_application)**<br/>
Web application or website that interacts with the user by dynamically rewriting the current web page with new data from the web server.


**[Single Sign-on (SSO)](https://en.wikipedia.org/wiki/Single_sign-on)**<br/>
Authentication scheme that allows a user to log in with a single ID and password to any of several related, yet independent, software systems.


**Upstream**<br/>
_(In the context of authentication/authorization)_ API whose endpoints must be protected by the auth system; the unprotected service in front of which a protection layer is added (by connecting with a Policy Decision Point).


**User-based Access Control (UBAC)**<br/>
Authorization model that grants/denies access to resources based on claims of the identity (attributes of the user).


**[User-Managed Access (UMA)](https://en.wikipedia.org/wiki/User-Managed_Access)**<br/>
OAuth2-based access management protocol, used for users of an auth server to control the authorization process, i.e. directly granting/denying access to user-owned resources to other requesting parties.
