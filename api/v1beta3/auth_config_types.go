/*
Copyright 2020 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta3

import (
	k8score "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

const (
	// The following constants are used to identify the different methods of authentication.
	UnknownAuthenticationMethod AuthenticationMethod = iota
	ApiKeyAuthentication
	JwtAuthentication
	OAuth2TokenIntrospectionAuthentication
	KubernetesTokenReviewAuthentication
	X509ClientCertificateAuthentication
	PlainIdentityAuthentication
	AnonymousAccessAuthentication

	// The following constants are used to identify the different methods of metadata fetching.
	UnknownMetadataMethod MetadataMethod = iota
	HttpMetadata
	UserInfoMetadata
	UmaResourceMetadata

	// The following constants are used to identify the different methods of authorization.
	UnknownAuthorizationMethod AuthorizationMethod = iota
	PatternMatchingAuthorization
	OpaAuthorization
	KubernetesSubjectAccessReviewAuthorization
	SpiceDBAuthorization

	// The following constants are used to identify the different methods of auth response.
	UnknownAuthResponseMethod AuthResponseMethod = iota
	PlainAuthResponse
	JsonAuthResponse
	WristbandAuthResponse

	// The following constants are used to identify the different methods of callback functions.
	UnknownCallbackMethod CallbackMethod = iota
	HttpCallback

	// The following constants are used to identify the different types of credentials.
	UnknownCredentialsType CredentialsType = iota
	AuthorizationHeaderCredentials
	CustomHeaderCredentials
	QueryStringCredentials
	CookieCredentials

	// Status conditions
	StatusConditionAvailable StatusConditionType = "Available"
	StatusConditionReady     StatusConditionType = "Ready"

	// Status reasons
	StatusReasonReconciling     string = "Reconciling"
	StatusReasonReconciled      string = "Reconciled"
	StatusReasonInvalidResource string = "Invalid"
	StatusReasonHostsLinked     string = "HostsLinked"
	StatusReasonHostsNotLinked  string = "HostsNotLinked"
	StatusReasonCachingError    string = "CachingError"
	StatusReasonUnknown         string = "Unknown"

	EvaluatorDefaultCacheTTL = 60
)

type AuthenticationMethod int8
type MetadataMethod int8
type AuthorizationMethod int8
type AuthResponseMethod int8
type CallbackMethod int8
type CredentialsType int8

type StatusConditionType string

// AuthConfig is the schema for Authorino's AuthConfig API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.summary.ready`,description="Ready for all hosts"
// +kubebuilder:printcolumn:name="Hosts",type=string,JSONPath=`.status.summary.numHostsReady`,description="Number of hosts ready"
// +kubebuilder:printcolumn:name="Authentication",type=integer,JSONPath=`.status.summary.numIdentitySources`,description="Number of trusted identity sources",priority=2
// +kubebuilder:printcolumn:name="Metadata",type=integer,JSONPath=`.status.summary.numMetadataSources`,description="Number of external metadata sources",priority=2
// +kubebuilder:printcolumn:name="Authorization",type=integer,JSONPath=`.status.summary.numAuthorizationPolicies`,description="Number of authorization policies",priority=2
// +kubebuilder:printcolumn:name="Response",type=integer,JSONPath=`.status.summary.numResponseItems`,description="Number of items added to the authorization response",priority=2
// +kubebuilder:printcolumn:name="Wristband",type=boolean,JSONPath=`.status.summary.festivalWristbandEnabled`,description="Whether issuing Festival Wristbands",priority=2
type AuthConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthConfigSpec   `json:"spec,omitempty"`
	Status AuthConfigStatus `json:"status,omitempty"`
}

// Specifies the desired state of the AuthConfig resource, i.e. the authencation/authorization scheme to be applied to protect the matching service hosts.
type AuthConfigSpec struct {
	// The list of public host names of the services protected by this authentication/authorization scheme.
	// Authorino uses the requested host to lookup for the corresponding authentication/authorization configs to enforce.
	Hosts []string `json:"hosts"`

	// Named sets of patterns that can be referred in `when` conditions and in pattern-matching authorization policy rules.
	// +optional
	NamedPatterns map[string]PatternExpressions `json:"patterns,omitempty"`

	// Overall conditions for the AuthConfig to be enforced.
	// If omitted, the AuthConfig will be enforced at all requests.
	// If present, all conditions must match for the AuthConfig to be enforced; otherwise, Authorino skips the AuthConfig and returns to the auth request with status OK.
	// +optional
	Conditions []PatternExpressionOrRef `json:"when,omitempty"`

	// Authentication configs.
	// At least one config MUST evaluate to a valid identity object for the auth request to be successful.
	// +optional
	Authentication map[string]AuthenticationSpec `json:"authentication,omitempty"`

	// Metadata sources.
	// Authorino fetches auth metadata as JSON from sources specified in this config.
	// +optional
	Metadata map[string]MetadataSpec `json:"metadata,omitempty"`

	// Authorization policies.
	// All policies MUST evaluate to "allowed = true" for the auth request be successful.
	// +optional
	Authorization map[string]AuthorizationSpec `json:"authorization,omitempty"`

	// Response items.
	// Authorino builds custom responses to the client of the auth request.
	// +optional
	Response *ResponseSpec `json:"response,omitempty"`

	// Callback functions.
	// Authorino sends callbacks at the end of the auth pipeline to the endpoints specified in this config.
	// +optional
	Callbacks map[string]CallbackSpec `json:"callbacks,omitempty"`
}

type PatternExpressions []PatternExpression

type PatternExpression struct {
	// Path selector to fetch content from the authorization JSON (e.g. 'request.method').
	// Any pattern supported by https://pkg.go.dev/github.com/tidwall/gjson can be used.
	// Authorino custom JSON path modifiers are also supported.
	Selector string `json:"selector,omitempty"`
	// The binary operator to be applied to the content fetched from the authorization JSON, for comparison with "value".
	// Possible values are: "eq" (equal to), "neq" (not equal to), "incl" (includes; for arrays), "excl" (excludes; for arrays), "matches" (regex)
	Operator PatternExpressionOperator `json:"operator,omitempty"`
	// The value of reference for the comparison with the content fetched from the authorization JSON.
	// If used with the "matches" operator, the value must compile to a valid Golang regex.
	Value string `json:"value,omitempty"`
}

type CelExpression string

type CelPredicate struct {
	// A Common Expression Language (CEL) expression that evaluates to a boolean.
	// String expressions are supported (https://pkg.go.dev/github.com/google/cel-go/ext#Strings).
	Predicate string `json:"predicate,omitempty"`
}

// +kubebuilder:validation:Enum:=eq;neq;incl;excl;matches
type PatternExpressionOperator string

type PatternExpressionOrRef struct {
	PatternExpression `json:",omitempty"`
	PatternRef        `json:",omitempty"`
	CelPredicate      `json:",omitempty"`
	// A list of pattern expressions to be evaluated as a logical AND.
	All []UnstructuredPatternExpressionOrRef `json:"all,omitempty"`
	// A list of pattern expressions to be evaluated as a logical OR.
	Any []UnstructuredPatternExpressionOrRef `json:"any,omitempty"`
}

type UnstructuredPatternExpressionOrRef struct {
	// +kubebuilder:pruning:PreserveUnknownFields
	PatternExpressionOrRef `json:",omitempty"`
}

type PatternRef struct {
	// Reference to a named set of pattern expressions
	Name string `json:"patternRef,omitempty"`
}

type NamedValuesOrSelectors map[string]ValueOrSelector

type ValueOrSelector struct {
	// Static value
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Value k8sruntime.RawExtension `json:"value,omitempty"`

	// Simple path selector to fetch content from the authorization JSON (e.g. 'request.method') or a string template with variables that resolve to patterns (e.g. "Hello, {auth.identity.name}!").
	// Any pattern supported by https://pkg.go.dev/github.com/tidwall/gjson can be used.
	// The following Authorino custom modifiers are supported: @extract:{sep:" ",pos:0}, @replace{old:"",new:""}, @case:upper|lower, @base64:encode|decode and @strip.
	Selector string `json:"selector,omitempty"`

	// A Common Expression Language (CEL) expression that evaluates to a value.
	// String expressions are supported (https://pkg.go.dev/github.com/google/cel-go/ext#Strings).
	Expression CelExpression `json:"expression,omitempty"`
}

type CommonEvaluatorSpec struct {
	// Priority group of the config.
	// All configs in the same priority group are evaluated concurrently; consecutive priority groups are evaluated sequentially.
	// +optional
	// +kubebuilder:default:=0
	Priority int `json:"priority,omitempty"`

	// Whether this config should generate individual observability metrics
	// +optional
	// +kubebuilder:default:=false
	Metrics bool `json:"metrics,omitempty"`

	// Conditions for Authorino to enforce this config.
	// If omitted, the config will be enforced for all requests.
	// If present, all conditions must match for the config to be enforced; otherwise, the config will be skipped.
	// +optional
	Conditions []PatternExpressionOrRef `json:"when,omitempty"`

	// Caching options for the resolved object returned when applying this config.
	// Omit it to avoid caching objects for this config.
	// +optional
	Cache *EvaluatorCaching `json:"cache,omitempty"`
}

type EvaluatorCaching struct {
	// Key used to store the entry in the cache.
	// The resolved key must be unique within the scope of this particular config.
	Key ValueOrSelector `json:"key"`

	// Duration (in seconds) of the external data in the cache before pulled again from the source.
	// +optional
	// +kubebuilder:default:=60
	TTL int `json:"ttl,omitempty"`
}

type AuthenticationSpec struct {
	CommonEvaluatorSpec `json:",omitempty"`

	// Defines where credentials are required to be passed in the request for authentication based on this config.
	// If omitted, it defaults to credentials passed in the HTTP Authorization header and the "Bearer" prefix prepended to the secret credential value.
	// +optional
	Credentials Credentials `json:"credentials,omitempty"`

	// Overrides the resolved identity object by setting the additional properties (claims) specified in this config,
	// before appending the object to the authorization JSON.
	// It requires the resolved identity object to always be a JSON object.
	// Do not use this option with identity objects of other JSON types (array, string, etc).
	// +optional
	Overrides ExtendedProperties `json:"overrides,omitempty"`

	// Set default property values (claims) for the resolved identity object, that are set before appending the object to
	// the authorization JSON. If the property is already present in the resolved identity object, the default value is ignored.
	// It requires the resolved identity object to always be a JSON object.
	// Do not use this option with identity objects of other JSON types (array, string, etc).
	// +optional
	Defaults ExtendedProperties `json:"defaults,omitempty"`

	AuthenticationMethodSpec `json:""`
}

func (s *AuthenticationSpec) GetMethod() AuthenticationMethod {
	if s.ApiKey != nil {
		return ApiKeyAuthentication
	} else if s.Jwt != nil {
		return JwtAuthentication
	} else if s.OAuth2TokenIntrospection != nil {
		return OAuth2TokenIntrospectionAuthentication
	} else if s.X509ClientCertificate != nil {
		return X509ClientCertificateAuthentication
	} else if s.KubernetesTokenReview != nil {
		return KubernetesTokenReviewAuthentication
	} else if s.Plain != nil {
		return PlainIdentityAuthentication
	} else if s.AnonymousAccess != nil {
		return AnonymousAccessAuthentication
	}
	return UnknownAuthenticationMethod
}

type Credentials struct {
	AuthorizationHeader *Prefixed     `json:"authorizationHeader,omitempty"`
	CustomHeader        *CustomHeader `json:"customHeader,omitempty"`
	QueryString         *Named        `json:"queryString,omitempty"`
	Cookie              *Named        `json:"cookie,omitempty"`
}

func (c *Credentials) GetType() CredentialsType {
	if c.AuthorizationHeader != nil {
		return AuthorizationHeaderCredentials
	} else if c.CustomHeader != nil {
		return CustomHeaderCredentials
	} else if c.QueryString != nil {
		return QueryStringCredentials
	} else if c.Cookie != nil {
		return CookieCredentials
	}
	return UnknownCredentialsType
}

type Named struct {
	Name string `json:"name"`
}

type Prefixed struct {
	Prefix string `json:"prefix,omitempty"`
}

type CustomHeader struct {
	Named `json:""`
}

type ExtendedProperties NamedValuesOrSelectors

type AuthenticationMethodSpec struct {
	// Authentication based on API keys stored in Kubernetes secrets.
	ApiKey *ApiKeyAuthenticationSpec `json:"apiKey,omitempty"`
	// Authentication based on JWT tokens.
	Jwt *JwtAuthenticationSpec `json:"jwt,omitempty"`
	// Authentication by OAuth2 token introspection.
	OAuth2TokenIntrospection *OAuth2TokenIntrospectionSpec `json:"oauth2Introspection,omitempty"`
	// Authentication by Kubernetes token review.
	KubernetesTokenReview *KubernetesTokenReviewSpec `json:"kubernetesTokenReview,omitempty"`
	// Authentication based on client X.509 certificates.
	// The certificates presented by the clients must be signed by a trusted CA whose certificates are stored in Kubernetes secrets.
	X509ClientCertificate *X509ClientCertificateAuthenticationSpec `json:"x509,omitempty"`
	// Identity object extracted from the context.
	// Use this method when authentication is performed beforehand by a proxy and the resulting object passed to Authorino as JSON in the auth request.
	Plain *PlainIdentitySpec `json:"plain,omitempty"`
	// Anonymous access.
	AnonymousAccess *AnonymousAccessSpec `json:"anonymous,omitempty"`
}

// Settings to select the API key Kubernetes secrets.
type ApiKeyAuthenticationSpec struct {
	// Label selector used by Authorino to match secrets from the cluster storing valid credentials to authenticate to this service
	Selector *metav1.LabelSelector `json:"selector"`

	// Whether Authorino should look for API key secrets in all namespaces or only in the same namespace as the AuthConfig.
	// Enabling this option in namespaced Authorino instances has no effect.
	// +optional
	// +kubebuilder:default:=false
	AllNamespaces bool `json:"allNamespaces,omitempty"`

	// List of keys within the selected Kubernetes secret that contain valid API credentials.
	// Authorino will attempt to authenticate using the first key that matches.
	// If no match is found, authentication will fail.
	// +optional
	KeySelectors []string `json:"keySelectors,omitempty"`
}

// Settings to fetch the JSON Web Key Set (JWKS) for the JWT authentication.
type JwtAuthenticationSpec struct {
	// URL of the issuer of the JWT.
	// If `jwksUrl` is omitted, Authorino will append the path to the OpenID Connect Well-Known Discovery endpoint
	// (i.e. "/.well-known/openid-configuration") to this URL, to discover the OIDC configuration where to obtain
	// the "jkws_uri" claim from.
	// The value must coincide with the value of  the "iss" (issuer) claim of the discovered OpenID Connect configuration.
	// +optional
	IssuerUrl string `json:"issuerUrl"`

	// Decides how long to wait before refreshing the JWKS (in seconds).
	// If omitted, Authorino will never refresh the JWKS.
	// +optional
	TTL int `json:"ttl,omitempty"`
}

// Settings to perform the OAuth2 token introspection request.
type OAuth2TokenIntrospectionSpec struct {
	// The full URL of the token introspection endpoint.
	Url string `json:"endpoint"`

	// The token type hint for the token introspection.
	// If omitted, it defaults to "access_token".
	// +optional
	TokenTypeHint string `json:"tokenTypeHint,omitempty"`

	// Reference to a Kubernetes secret in the same namespace, that stores client credentials to the OAuth2 server.
	Credentials *k8score.LocalObjectReference `json:"credentialsRef"`
}

// Parameters of the Kubernetes TokenReview request
type KubernetesTokenReviewSpec struct {
	// The list of audiences (scopes) that must be claimed in a Kubernetes authentication token supplied in the request, and reviewed by Authorino.
	// If omitted, Authorino will review tokens expecting the host name of the requested protected service amongst the audiences.
	// +optional
	Audiences []string `json:"audiences,omitempty"`
}

// Settings to authenticate clients by X.509 certificates.
type X509ClientCertificateAuthenticationSpec struct {
	// Label selector used by Authorino to match secrets from the cluster storing trusted CA certificates to validate
	// clients trying to authenticate to this service
	Selector *metav1.LabelSelector `json:"selector"`

	// Whether Authorino should look for TLS secrets in all namespaces or only in the same namespace as the AuthConfig.
	// Enabling this option in namespaced Authorino instances has no effect.
	// +optional
	// +kubebuilder:default:=false
	AllNamespaces bool `json:"allNamespaces,omitempty"`
}

// Settings to extract the identity object from the context.
type PlainIdentitySpec struct {
	// Simple path selector to fetch content from the authorization JSON (e.g. 'request.method') or a string template with variables that resolve to patterns (e.g. "Hello, {auth.identity.name}!").
	// Any pattern supported by https://pkg.go.dev/github.com/tidwall/gjson can be used.
	// The following Authorino custom modifiers are supported: @extract:{sep:" ",pos:0}, @replace{old:"",new:""}, @case:upper|lower, @base64:encode|decode and @strip.
	Selector string `json:"selector,omitempty"`

	// A Common Expression Language (CEL) expression that evaluates to a value that represents an identity.
	// String expressions are supported (https://pkg.go.dev/github.com/google/cel-go/ext#Strings).
	Expression CelExpression `json:"expression,omitempty"`
}

type AnonymousAccessSpec struct{}

type MetadataSpec struct {
	CommonEvaluatorSpec `json:""`
	MetadataMethodSpec  `json:""`
}

func (s *MetadataSpec) GetMethod() MetadataMethod {
	if s.Http != nil {
		return HttpMetadata
	} else if s.UserInfo != nil {
		return UserInfoMetadata
	} else if s.Uma != nil {
		return UmaResourceMetadata
	}
	return UnknownMetadataMethod
}

type MetadataMethodSpec struct {
	// External source of auth metadata via HTTP request
	Http *HttpEndpointSpec `json:"http,omitempty"`
	// OpendID Connect UserInfo linked to an OIDC authentication config specified in this same AuthConfig.
	UserInfo *UserInfoMetadataSpec `json:"userInfo,omitempty"`
	// User-Managed Access (UMA) source of resource data.
	Uma *UmaMetadataSpec `json:"uma,omitempty"`
}

// Settings of the external HTTP request
type HttpEndpointSpec struct {
	// Endpoint URL of the HTTP service.
	// The value can include variable placeholders in the format "{selector}", where "selector" is any pattern supported
	// by https://pkg.go.dev/github.com/tidwall/gjson and selects value from the authorization JSON.
	// E.g. https://ext-auth-server.io/metadata?p={request.path}
	Url string `json:"url,omitempty"`

	// A Common Expression Language (CEL) expression that evaluates to a string endpoint URL of the HTTP service to call.
	// String expressions are supported (https://pkg.go.dev/github.com/google/cel-go/ext#Strings).
	UrlExpression CelExpression `json:"urlExpression,omitempty"`

	// HTTP verb used in the request to the service. Accepted values: GET (default), POST.
	// When the request method is POST, the authorization JSON is passed in the body of the request.
	// +optional
	// +kubebuilder:default:=GET
	Method *HttpMethod `json:"method,omitempty"`

	// Raw body of the HTTP request.
	// Supersedes 'bodyParameters'; use either one or the other.
	// Use it with method=POST; for GET requests, set parameters as query string in the 'endpoint' (placeholders can be used).
	// +optional
	Body *ValueOrSelector `json:"body,omitempty"`

	// Custom parameters to encode in the body of the HTTP request.
	// Superseded by 'body'; use either one or the other.
	// Use it with method=POST; for GET requests, set parameters as query string in the 'endpoint' (placeholders can be used).
	// +optional
	Parameters NamedValuesOrSelectors `json:"bodyParameters,omitempty"`

	// Content-Type of the request body. Shapes how 'bodyParameters' are encoded.
	// Use it with method=POST; for GET requests, Content-Type is automatically set to 'text/plain'.
	// +optional
	// +kubebuilder:default:=application/x-www-form-urlencoded
	ContentType HttpContentType `json:"contentType,omitempty"`

	// Custom headers in the HTTP request.
	// +optional
	Headers NamedValuesOrSelectors `json:"headers,omitempty"`

	// Reference to a Secret key whose value will be passed by Authorino in the request.
	// The HTTP service can use the shared secret to authenticate the origin of the request.
	// Ignored if used together with oauth2.
	// +optional
	SharedSecret *SecretKeyReference `json:"sharedSecretRef,omitempty"`

	// Authentication with the HTTP service by OAuth2 Client Credentials grant.
	// +optional
	OAuth2 *OAuth2ClientAuthentication `json:"oauth2,omitempty"`

	// Defines where client credentials will be passed in the request to the service.
	// If omitted, it defaults to client credentials passed in the HTTP Authorization header and the "Bearer" prefix expected prepended to the secret value.
	// +optional
	Credentials Credentials `json:"credentials,omitempty"`
}

// +kubebuilder:validation:Enum:=GET;POST;PUT;PATCH;DELETE;HEAD;OPTIONS;CONNECT;TRACE
type HttpMethod string

// +kubebuilder:validation:Enum:=application/x-www-form-urlencoded;application/json
type HttpContentType string

// Reference to a Kubernetes secret
type SecretKeyReference struct {
	// The name of the secret in the Authorino's namespace to select from.
	Name string `json:"name"`

	// The key of the secret to select from.  Must be a valid secret key.
	Key string `json:"key"`
}

// Settings for OAuth2 client authentication with the external service
type OAuth2ClientAuthentication struct {
	// Token endpoint URL of the OAuth2 resource server.
	TokenUrl string `json:"tokenUrl"`
	// OAuth2 Client ID.
	ClientId string `json:"clientId"`
	// Reference to a Kuberentes Secret key that stores that OAuth2 Client Secret.
	ClientSecret SecretKeyReference `json:"clientSecretRef"`
	// Optional scopes for the client credentials grant, if supported by he OAuth2 server.
	Scopes []string `json:"scopes,omitempty"`
	// Optional extra parameters for the requests to the token URL.
	ExtraParams map[string]string `json:"extraParams,omitempty"`
	// Caches and reuses the token until expired.
	// Set it to false to force fetch the token at every authorization request regardless of expiration.
	// +kubebuilder:default:=true
	Cache *bool `json:"cache,omitempty"`
}

// Settings of the OpendID Connect UserInfo linked to an OIDC-enabled JWT authentication config of this same AuthConfig.
type UserInfoMetadataSpec struct {
	// The name of an OIDC-enabled JWT authentication config whose OpenID Connect configuration discovered includes the OIDC "userinfo_endpoint" claim.
	IdentitySource string `json:"identitySource"`
}

// Settings of the User-Managed Access (UMA) source of resource data.
type UmaMetadataSpec struct {
	// The endpoint of the UMA server.
	// The value must coincide with the "issuer" claim of the UMA config discovered from the well-known uma configuration endpoint.
	Endpoint string `json:"endpoint"`

	// Reference to a Kubernetes secret in the same namespace, that stores client credentials to the resource registration API of the UMA server.
	Credentials *k8score.LocalObjectReference `json:"credentialsRef"`
}

type AuthorizationSpec struct {
	CommonEvaluatorSpec     `json:""`
	AuthorizationMethodSpec `json:""`
}

func (s *AuthorizationSpec) GetMethod() AuthorizationMethod {
	if s.PatternMatching != nil {
		return PatternMatchingAuthorization
	} else if s.Opa != nil {
		return OpaAuthorization
	} else if s.KubernetesSubjectAccessReview != nil {
		return KubernetesSubjectAccessReviewAuthorization
	} else if s.SpiceDB != nil {
		return SpiceDBAuthorization
	}
	return UnknownAuthorizationMethod
}

type AuthorizationMethodSpec struct {
	// Pattern-matching authorization rules.
	PatternMatching *PatternMatchingAuthorizationSpec `json:"patternMatching,omitempty"`
	// Open Policy Agent (OPA) Rego policy.
	Opa *OpaAuthorizationSpec `json:"opa,omitempty"`
	// Authorization by Kubernetes SubjectAccessReview
	KubernetesSubjectAccessReview *KubernetesSubjectAccessReviewAuthorizationSpec `json:"kubernetesSubjectAccessReview,omitempty"`
	// Authorization decision delegated to external Authzed/SpiceDB server.
	SpiceDB *SpiceDBAuthorizationSpec `json:"spicedb,omitempty"`
}

type PatternMatchingAuthorizationSpec struct {
	Patterns []PatternExpressionOrRef `json:"patterns"`
}

// Settings of the Open Policy Agent (OPA) authorization.
type OpaAuthorizationSpec struct {
	// Authorization policy as a Rego language document.
	// The Rego document must include the "allow" condition, set by Authorino to "false" by default (i.e. requests are unauthorized unless changed).
	// The Rego document must NOT include the "package" declaration in line 1.
	Rego string `json:"rego,omitempty"`

	// Settings for fetching the OPA policy from an external registry.
	// Use it alternatively to 'rego'.
	// For the configurations of the HTTP request, the following options are not implemented: 'method', 'body', 'bodyParameters',
	// 'contentType', 'headers', 'oauth2'. Use it only with: 'url', 'sharedSecret', 'credentials'.
	External *ExternalOpaPolicy `json:"externalPolicy,omitempty"`

	// Returns the value of all Rego rules in the virtual document. Values can be read in subsequent evaluators/phases of the Auth Pipeline.
	// Otherwise, only the default `allow` rule will be exposed.
	// Returning all Rego rules can affect performance of OPA policies during reconciliation (policy precompile) and at runtime.
	// +kubebuilder:default:=false
	AllValues bool `json:"allValues,omitempty"`
}

// ExternalOpaPolicy sets the configs for fetching OPA policies from an external source.
type ExternalOpaPolicy struct {
	*HttpEndpointSpec `json:""`

	// Duration (in seconds) of the external data in the cache before pulled again from the source.
	TTL int `json:"ttl,omitempty"`
}

// Parameters of the Kubernetes SubjectAccessReview request.
type KubernetesSubjectAccessReviewAuthorizationSpec struct {
	// User to check for authorization in the Kubernetes RBAC.
	// Omit it to check for group authorization only.
	User *ValueOrSelector `json:"user,omitempty"`

	// Groups the user must be a member of or, if `user` is omitted, the groups to check for authorization in the Kubernetes RBAC.
	// Deprecated: Use authorizationGroups instead.
	Groups []string `json:"groups,omitempty"`

	// Groups to check for existing permission in the Kubernetes RBAC alternatively to a specific user. This is typically obtained from a list of groups the user is a member of. Must be a static list of group names or dynamically resolve to one from the Authorization JSON.
	AuthorizationGroups *ValueOrSelector `json:"authorizationGroups,omitempty"`

	// Use resourceAttributes to check permissions on Kubernetes resources.
	// If omitted, it performs a non-resource SubjectAccessReview, with verb and path inferred from the request.
	// +optional
	ResourceAttributes *KubernetesSubjectAccessReviewResourceAttributesSpec `json:"resourceAttributes,omitempty"`
}

type KubernetesSubjectAccessReviewResourceAttributesSpec struct {
	// API group of the resource.
	// Use '*' for all API groups.
	Group ValueOrSelector `json:"group,omitempty"`
	// Resource kind
	// Use '*' for all resource kinds.
	Resource ValueOrSelector `json:"resource,omitempty"`
	// Subresource kind
	SubResource ValueOrSelector `json:"subresource,omitempty"`
	// Resource name
	// Omit it to check for authorization on all resources of the specified kind.
	Name ValueOrSelector `json:"name,omitempty"`
	// Namespace where the user must have permissions on the resource.
	Namespace ValueOrSelector `json:"namespace,omitempty"`
	// Verb to check for authorization on the resource.
	// Use '*' for all verbs.
	Verb ValueOrSelector `json:"verb,omitempty"`
}

// Settings of the check request to the external SpiceDB server.
type SpiceDBAuthorizationSpec struct {
	// Hostname and port number to the GRPC interface of the SpiceDB server (e.g. spicedb:50051).
	Endpoint string `json:"endpoint"`

	// Insecure HTTP connection (i.e. disables TLS verification)
	Insecure bool `json:"insecure,omitempty"`

	// Reference to a Secret key whose value will be used by Authorino to authenticate with the Authzed service.
	SharedSecret *SecretKeyReference `json:"sharedSecretRef,omitempty"`

	// The subject that will be checked for the permission or relation.
	Subject *SpiceDBObject `json:"subject,omitempty"`

	// The resource on which to check the permission or relation.
	Resource *SpiceDBObject `json:"resource,omitempty"`

	// The name of the permission (or relation) on which to execute the check.
	Permission ValueOrSelector `json:"permission,omitempty"`
}

type SpiceDBObject struct {
	Name ValueOrSelector `json:"name,omitempty"`
	Kind ValueOrSelector `json:"kind,omitempty"`
}

// Settings of the custom auth response.
type ResponseSpec struct {
	// Customizations on the denial status attributes when the request is unauthenticated.
	// For integration of Authorino via proxy, the proxy must honour the response status attributes specified in this config.
	// Default: 401 Unauthorized
	// +optional
	Unauthenticated *DenyWithSpec `json:"unauthenticated,omitempty"`

	// Customizations on the denial status attributes when the request is unauthorized.
	// For integration of Authorino via proxy, the proxy must honour the response status attributes specified in this config.
	// Default: 403 Forbidden
	// +optional
	Unauthorized *DenyWithSpec `json:"unauthorized,omitempty"`

	// Response items to be included in the auth response when the request is authenticated and authorized.
	// For integration of Authorino via proxy, the proxy must use these settings to propagate dynamic metadata and/or inject data in the request.
	// +optional
	Success WrappedSuccessResponseSpec `json:"success,omitempty"`
}

// +kubebuilder:validation:Minimum:=300
// +kubebuilder:validation:Maximum:=599
type DenyWithCode int64

// Setting of the custom denial response.
type DenyWithSpec struct {
	// HTTP status code to override the default denial status code.
	Code DenyWithCode `json:"code,omitempty"`

	// HTTP message to override the default denial message.
	Message *ValueOrSelector `json:"message,omitempty"`

	// HTTP response headers to override the default denial headers.
	Headers NamedValuesOrSelectors `json:"headers,omitempty"`

	// HTTP response body to override the default denial body.
	Body *ValueOrSelector `json:"body,omitempty"`
}

// Settings of the custom success response.
type WrappedSuccessResponseSpec struct {
	// Custom success response items wrapped as HTTP headers.
	// For integration of Authorino via proxy, the proxy must use these settings to inject data in the request.
	Headers map[string]HeaderSuccessResponseSpec `json:"headers,omitempty"`

	// Custom success response items wrapped as HTTP headers.
	// For integration of Authorino via proxy, the proxy must use these settings to propagate dynamic metadata.
	// See https://www.envoyproxy.io/docs/envoy/latest/configuration/advanced/well_known_dynamic_metadata
	DynamicMetadata map[string]SuccessResponseSpec `json:"dynamicMetadata,omitempty"`
}

type HeaderSuccessResponseSpec struct {
	SuccessResponseSpec `json:",omitempty"`
}

// Settings of the success custom response item.
type SuccessResponseSpec struct {
	CommonEvaluatorSpec    `json:""`
	AuthResponseMethodSpec `json:""`

	// The key used to add the custom response item (name of the HTTP header or root property of the Dynamic Metadata object).
	// If omitted, it will be set to the name of the response config.
	Key string `json:"key,omitempty"`
}

func (s *SuccessResponseSpec) GetMethod() AuthResponseMethod {
	if s.Plain != nil {
		return PlainAuthResponse
	} else if s.Json != nil {
		return JsonAuthResponse
	} else if s.Wristband != nil {
		return WristbandAuthResponse
	}
	return UnknownAuthResponseMethod
}

// Settings of the custom success response item.
type AuthResponseMethodSpec struct {
	// Plain text content
	Plain *PlainAuthResponseSpec `json:"plain,omitempty"`
	// JSON object
	// Specify it as the list of properties of the object, whose values can combine static values and values selected from the authorization JSON.
	Json *JsonAuthResponseSpec `json:"json,omitempty"`
	// Authorino Festival Wristband token
	Wristband *WristbandAuthResponseSpec `json:"wristband,omitempty"`
}

// Static value or selector to set the plain custom response item.
type PlainAuthResponseSpec ValueOrSelector

// List of properties of the JSON object to set the custom response item
// The values can be static or selected from the authorization JSON.
type JsonAuthResponseSpec struct {
	Properties NamedValuesOrSelectors `json:"properties"`
}

// Settings of the Festival Wristband token custom response item.
type WristbandAuthResponseSpec struct {
	// The endpoint to the Authorino service that issues the wristband (format: <scheme>://<host>:<port>/<realm>, where <realm> = <namespace>/<authorino-auth-config-resource-name/wristband-config-name)
	Issuer string `json:"issuer"`
	// Any claims to be added to the wristband token apart from the standard JWT claims (iss, iat, exp) added by default.
	CustomClaims NamedValuesOrSelectors `json:"customClaims,omitempty"`
	// Time span of the wristband token, in seconds.
	TokenDuration *int64 `json:"tokenDuration,omitempty"`
	// Reference by name to Kubernetes secrets and corresponding signing algorithms.
	// The secrets must contain a `key.pem` entry whose value is the signing key formatted as PEM.
	SigningKeyRefs []*WristbandSigningKeyRef `json:"signingKeyRefs"`
}

type WristbandSigningKeyRef struct {
	// Name of the signing key.
	// The value is used to reference the Kubernetes secret that stores the key and in the `kid` claim of the wristband token header.
	Name string `json:"name"`

	// Algorithm to sign the wristband token using the signing key provided
	Algorithm WristbandSigningKeyAlgorithm `json:"algorithm"`
}

// +kubebuilder:validation:Enum:=ES256;ES384;ES512;RS256;RS384;RS512
type WristbandSigningKeyAlgorithm string

type CallbackSpec struct {
	CommonEvaluatorSpec `json:""`
	CallbackMethodSpec  `json:""`
}

func (s *CallbackSpec) GetMethod() CallbackMethod {
	if s.Http != nil {
		return HttpCallback
	}
	return UnknownCallbackMethod
}

// Settings of the callback function.
type CallbackMethodSpec struct {
	Http *HttpEndpointSpec `json:"http"` // make this 'omitempty' if other alternate methods are added
}

// AuthConfigStatus defines the observed state of AuthConfig
type AuthConfigStatus struct {
	Conditions []AuthConfigStatusCondition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
	Summary    AuthConfigStatusSummary     `json:"summary,omitempty"`
}

func (s *AuthConfigStatus) Ready() bool {
	for _, condition := range s.Conditions {
		if condition.Type == StatusConditionReady {
			return condition.Status == k8score.ConditionTrue
		}
	}
	return false
}

type AuthConfigStatusCondition struct {
	// Type of condition
	Type StatusConditionType `json:"type"`

	// Status of the condition, one of True, False, Unknown.
	Status k8score.ConditionStatus `json:"status"`

	// Last time the condition transit from one status to another.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`

	// (brief) reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Human readable message indicating details about last transition.
	// +optional
	Message string `json:"message,omitempty"`

	// Last time the condition was updated
	// +optional
	LastUpdatedTime *metav1.Time `json:"lastUpdatedTime,omitempty"`
}

type AuthConfigStatusSummary struct {
	// Whether all hosts from spec.hosts have been linked to the resource in the index
	Ready bool `json:"ready"`

	// Lists the hosts from spec.hosts linked to the resource in the index
	HostsReady []string `json:"hostsReady"`

	// Number of hosts from spec.hosts linked to the resource in the index, compared to the total number of hosts in spec.hosts
	NumHostsReady string `json:"numHostsReady"`

	// Number of trusted sources of identity for authentication in the AuthConfig
	NumIdentitySources int64 `json:"numIdentitySources"`

	// Number of sources of external metadata in the AuthConfig
	NumMetadataSources int64 `json:"numMetadataSources"`

	// Number of authorization policies in the AuthConfig
	NumAuthorizationPolicies int64 `json:"numAuthorizationPolicies"`

	// Number of custom authorization response items in the AuthConfig
	NumResponseItems int64 `json:"numResponseItems"`

	// Indicator of whether the AuthConfig issues Festival Wristband tokens on successful evaluation of the AuthConfig (access granted)
	FestivalWristbandEnabled bool `json:"festivalWristbandEnabled"`
}

// AuthConfigList contains a list of AuthConfig
// +kubebuilder:object:root=true
type AuthConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           AuthConfigs `json:"items"`
}

type AuthConfigs []AuthConfig

func (s AuthConfigs) Len() int {
	return len(s)
}

func (s AuthConfigs) Less(i, j int) bool {
	return s[i].CreationTimestamp.Before(&s[j].CreationTimestamp)
}

func (s AuthConfigs) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func init() {
	SchemeBuilder.Register(&AuthConfig{}, &AuthConfigList{})
}
