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

package v1beta1

import (
	k8score "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	TypeUnknown                      = "UNKNOWN"
	IdentityOAuth2                   = "IDENTITY_OAUTH2"
	IdentityOidc                     = "IDENTITY_OIDC"
	IdentityApiKey                   = "IDENTITY_APIKEY"
	IdentityMTLS                     = "IDENTITY_MTLS"
	IdentityKubernetesAuth           = "IDENTITY_KUBERNETESAUTH"
	IdentityAnonymous                = "IDENTITY_ANONYMOUS"
	IdentityPlain                    = "IDENTITY_PLAIN"
	MetadataUma                      = "METADATA_UMA"
	MetadataGenericHTTP              = "METADATA_GENERIC_HTTP"
	MetadataUserinfo                 = "METADATA_USERINFO"
	AuthorizationOPA                 = "AUTHORIZATION_OPA"
	AuthorizationJSONPatternMatching = "AUTHORIZATION_JSON"
	AuthorizationKubernetesAuthz     = "AUTHORIZATION_KUBERNETESAUTHZ"
	AuthorizationAuthzed             = "AUTHORIZATION_AUTHZED"
	ResponseWristband                = "RESPONSE_WRISTBAND"
	ResponseDynamicJSON              = "RESPONSE_DYNAMIC_JSON"
	CallbackHTTP                     = "CALLBACK_HTTP"
	EvaluatorDefaultCacheTTL         = 60

	// Status conditions
	StatusConditionAvailable ConditionType = "Available"
	StatusConditionReady     ConditionType = "Ready"

	// Status reasons
	StatusReasonReconciling     string = "Reconciling"
	StatusReasonReconciled      string = "Reconciled"
	StatusReasonInvalidResource string = "Invalid"
	StatusReasonHostsLinked     string = "HostsLinked"
	StatusReasonHostsNotLinked  string = "HostsNotLinked"
	StatusReasonCachingError    string = "CachingError"
	StatusReasonUnknown         string = "Unknown"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SecretKeyReference selects a key of a Secret.
type SecretKeyReference struct {
	// The name of the secret in the Authorino's namespace to select from.
	Name string `json:"name"`

	// The key of the secret to select from.  Must be a valid secret key.
	Key string `json:"key"`
}

// StaticOrDynamicValue is either a constant static string value or a config for fetching a value from a dynamic source (e.g. a path pattern of authorization JSON)
type StaticOrDynamicValue struct {
	// Static value
	Value string `json:"value,omitempty"`
	// Dynamic value
	ValueFrom ValueFrom `json:"valueFrom,omitempty"`
}

type ValueFrom struct {
	// Selector to fetch a value from the authorization JSON.
	// It can be any path pattern to fetch from the authorization JSON (e.g. 'context.request.http.host')
	// or a string template with variable placeholders that resolve to patterns (e.g. "Hello, {auth.identity.name}!").
	// Any patterns supported by https://pkg.go.dev/github.com/tidwall/gjson can be used.
	// The following string modifiers are available: @extract:{sep:" ",pos:0}, @replace{old:"",new:""}, @case:upper|lower, @base64:encode|decode and @strip.
	AuthJSON string `json:"authJSON,omitempty"`
}

type JsonProperty struct {
	// The name of the JSON property
	Name string `json:"name"`
	// Static value of the JSON property
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Value runtime.RawExtension `json:"value,omitempty"`
	// Dynamic value of the JSON property
	ValueFrom ValueFrom `json:"valueFrom,omitempty"`
}

type EvaluatorCaching struct {
	// Key used to store the entry in the cache.
	// Cache entries from different metadata configs are stored and managed separately regardless of the key.
	Key StaticOrDynamicValue `json:"key"`
	// Duration (in seconds) of the external data in the cache before pulled again from the source.
	// +kubebuilder:default:=60
	TTL int `json:"ttl,omitempty"`
}

// Specifies the desired state of the AuthConfig resource, i.e. the authencation/authorization scheme to be applied to protect the matching service hosts.
type AuthConfigSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// The list of public host names of the services protected by this authentication/authorization scheme.
	// Authorino uses the requested host to lookup for the corresponding authentication/authorization configs to enforce.
	Hosts []string `json:"hosts"`

	// Named sets of JSON patterns that can be referred in `when` conditionals and in JSON-pattern matching policy rules.
	Patterns map[string]JSONPatternExpressions `json:"patterns,omitempty"`

	// Conditions for the AuthConfig to be enforced.
	// If omitted, the AuthConfig will be enforced for all requests.
	// If present, all conditions must match for the AuthConfig to be enforced; otherwise, Authorino skips the AuthConfig and returns immediately with status OK.
	Conditions []JSONPattern `json:"when,omitempty"`

	// List of identity sources/authentication modes.
	// At least one config of this list MUST evaluate to a valid identity for a request to be successful in the identity verification phase.
	Identity []*Identity `json:"identity,omitempty"`

	// List of metadata source configs.
	// Authorino fetches JSON content from sources on this list on every request.
	Metadata []*Metadata `json:"metadata,omitempty"`

	// Authorization is the list of authorization policies.
	// All policies in this list MUST evaluate to "true" for a request be successful in the authorization phase.
	Authorization []*Authorization `json:"authorization,omitempty"`

	// List of response configs.
	// Authorino gathers data from the auth pipeline to build custom responses for the client.
	Response []*Response `json:"response,omitempty"`

	// List of callback configs.
	// Authorino sends callbacks to specified endpoints at the end of the auth pipeline.
	Callbacks []*Callback `json:"callbacks,omitempty"`

	// Custom denial response codes, statuses and headers to override default 40x's.
	DenyWith *DenyWith `json:"denyWith,omitempty"`
}

type JSONPattern struct {
	JSONPatternRef        `json:",omitempty"`
	JSONPatternExpression `json:",omitempty"`
}

type JSONPatternRef struct {
	// Name of a named pattern
	JSONPatternName string `json:"patternRef,omitempty"`
}

type JSONPatternExpressions []JSONPatternExpression

type JSONPatternExpression struct {
	// Any pattern supported by https://pkg.go.dev/github.com/tidwall/gjson.
	// The value is used to fetch content from the input authorization JSON built by Authorino along the identity and metadata phases.
	Selector string `json:"selector,omitempty"`
	// The binary operator to be applied to the content fetched from the authorization JSON, for comparison with "value".
	// Possible values are: "eq" (equal to), "neq" (not equal to), "incl" (includes; for arrays), "excl" (excludes; for arrays), "matches" (regex)
	Operator JSONPatternOperator `json:"operator,omitempty"`
	// The value of reference for the comparison with the content fetched from the authorization JSON.
	// If used with the "matches" operator, the value must compile to a valid Golang regex.
	Value string `json:"value,omitempty"`
}

// +kubebuilder:validation:Enum:=eq;neq;incl;excl;matches
type JSONPatternOperator string

// +kubebuilder:validation:Enum:=authorization_header;custom_header;query;cookie
type Credentials_In string

type Credentials struct {
	// The location in the request where client credentials shall be passed on requests authenticating with this identity source/authentication mode.
	// +kubebuilder:default:=authorization_header
	In Credentials_In `json:"in,omitempty"`
	// Used in conjunction with the `in` parameter.
	// When used with `authorization_header`, the value is the prefix of the client credentials string, separated by a white-space, in the HTTP Authorization header (e.g. "Bearer", "Basic").
	// When used with `custom_header`, `query` or `cookie`, the value is the name of the HTTP header, query string parameter or cookie key, respectively.
	KeySelector string `json:"keySelector"`
}

// The identity source/authentication mode config.
// Apart from "name", one of the following parameters is required and only one of the following parameters is allowed: "oicd", "apiKey" or "kubernetes".
type Identity struct {
	// The name of this identity source/authentication mode.
	// It usually identifies a source of identities or group of users/clients of the protected service.
	// It can be used to refer to the resolved identity object in other configs.
	Name string `json:"name"`

	// Priority group of the config.
	// All configs in the same priority group are evaluated concurrently; consecutive priority groups are evaluated sequentially.
	// +kubebuilder:default:=0
	Priority int `json:"priority,omitempty"`

	// Whether this identity config should generate individual observability metrics
	// +kubebuilder:default:=false
	Metrics bool `json:"metrics,omitempty"`

	// Conditions for Authorino to enforce this identity config.
	// If omitted, the config will be enforced for all requests.
	// If present, all conditions must match for the config to be enforced; otherwise, the config will be skipped.
	Conditions []JSONPattern `json:"when,omitempty"`

	// Caching options for the identity resolved when applying this config.
	// Omit it to avoid caching identity objects for this config.
	Cache *EvaluatorCaching `json:"cache,omitempty"`

	// Defines where client credentials are required to be passed in the request for this identity source/authentication mode.
	// If omitted, it defaults to client credentials passed in the HTTP Authorization header and the "Bearer" prefix expected prepended to the credentials value (token, API key, etc).
	Credentials Credentials `json:"credentials,omitempty"`

	// Extends the resolved identity object with additional custom properties before appending to the authorization JSON.
	// It requires the resolved identity object to always be of the JSON type 'object'. Other JSON types (array, string, etc) will break.
	ExtendedProperties []JsonProperty `json:"extendedProperties,omitempty"`

	OAuth2         *Identity_OAuth2Config   `json:"oauth2,omitempty"`
	Oidc           *Identity_OidcConfig     `json:"oidc,omitempty"`
	APIKey         *Identity_APIKey         `json:"apiKey,omitempty"`
	MTLS           *Identity_MTLS           `json:"mtls,omitempty"`
	KubernetesAuth *Identity_KubernetesAuth `json:"kubernetes,omitempty"`
	Anonymous      *Identity_Anonymous      `json:"anonymous,omitempty"`
	Plain          *Identity_Plain          `json:"plain,omitempty"`
}

func (i *Identity) GetType() string {
	if i.OAuth2 != nil {
		return IdentityOAuth2
	} else if i.Oidc != nil {
		return IdentityOidc
	} else if i.APIKey != nil {
		return IdentityApiKey
	} else if i.MTLS != nil {
		return IdentityMTLS
	} else if i.KubernetesAuth != nil {
		return IdentityKubernetesAuth
	} else if i.Anonymous != nil {
		return IdentityAnonymous
	} else if i.Plain != nil {
		return IdentityPlain
	} else {
		return TypeUnknown
	}
}

type Identity_OAuth2Config struct {
	// The full URL of the token introspection endpoint.
	TokenIntrospectionUrl string `json:"tokenIntrospectionUrl"`
	// The token type hint for the token introspection.
	// If omitted, it defaults to "access_token".
	TokenTypeHint string `json:"tokenTypeHint,omitempty"`

	// Reference to a Kubernetes secret in the same namespace, that stores client credentials to the OAuth2 server.
	Credentials *k8score.LocalObjectReference `json:"credentialsRef"`
}

type Identity_OidcConfig struct {
	// Endpoint of the OIDC issuer.
	// Authorino will append to this value the well-known path to the OpenID Connect discovery endpoint (i.e. "/.well-known/openid-configuration"), used to automatically discover the OpenID Connect configuration, whose set of claims is expected to include (among others) the "jkws_uri" claim.
	// The value must coincide with the value of  the "iss" (issuer) claim of the discovered OpenID Connect configuration.
	Endpoint string `json:"endpoint"`
	// Decides how long to wait before refreshing the OIDC configuration (in seconds).
	TTL int `json:"ttl,omitempty"`
}

type Identity_APIKey struct {
	// Label selector used by Authorino to match secrets from the cluster storing valid credentials to authenticate to this service
	Selector *metav1.LabelSelector `json:"selector"`

	// Whether Authorino should look for API key secrets in all namespaces or only in the same namespace as the AuthConfig.
	// Enabling this option in namespaced Authorino instances has no effect.
	// +kubebuilder:default:=false
	AllNamespaces bool `json:"allNamespaces,omitempty"`
}

type Identity_MTLS struct {
	// Label selector used by Authorino to match secrets from the cluster storing trusted CA certificates to validate clients trying to authenticate to this service
	Selector *metav1.LabelSelector `json:"selector"`

	// Whether Authorino should look for TLS secrets in all namespaces or only in the same namespace as the AuthConfig.
	// Enabling this option in namespaced Authorino instances has no effect.
	// +kubebuilder:default:=false
	AllNamespaces bool `json:"allNamespaces,omitempty"`
}

type Identity_KubernetesAuth struct {
	// The list of audiences (scopes) that must be claimed in a Kubernetes authentication token supplied in the request, and reviewed by Authorino.
	// If omitted, Authorino will review tokens expecting the host name of the requested protected service amongst the audiences.
	Audiences []string `json:"audiences,omitempty"`
}

type Identity_Anonymous struct{}

type Identity_Plain ValueFrom

// The metadata config.
// Apart from "name", one of the following parameters is required and only one of the following parameters is allowed: "http", userInfo" or "uma".
type Metadata struct {
	// The name of the metadata source.
	// It can be used to refer to the resolved metadata object in other configs.
	Name string `json:"name"`

	// Priority group of the config.
	// All configs in the same priority group are evaluated concurrently; consecutive priority groups are evaluated sequentially.
	// +kubebuilder:default:=0
	Priority int `json:"priority,omitempty"`

	// Whether this metadata config should generate individual observability metrics
	// +kubebuilder:default:=false
	Metrics bool `json:"metrics,omitempty"`

	// Conditions for Authorino to apply this metadata config.
	// If omitted, the config will be applied for all requests.
	// If present, all conditions must match for the config to be applied; otherwise, the config will be skipped.
	Conditions []JSONPattern `json:"when,omitempty"`

	// Caching options for the external metadata fetched when applying this config.
	// Omit it to avoid caching metadata from this source.
	Cache *EvaluatorCaching `json:"cache,omitempty"`

	UserInfo    *Metadata_UserInfo    `json:"userInfo,omitempty"`
	UMA         *Metadata_UMA         `json:"uma,omitempty"`
	GenericHTTP *Metadata_GenericHTTP `json:"http,omitempty"`
}

func (m *Metadata) GetType() string {
	if m.UserInfo != nil {
		return MetadataUserinfo
	} else if m.UMA != nil {
		return MetadataUma
	} else if m.GenericHTTP != nil {
		return MetadataGenericHTTP
	}
	return TypeUnknown
}

// OpendID Connect UserInfo linked to an OIDC identity config of this same spec.
type Metadata_UserInfo struct {
	// The name of an OIDC identity source included in the "identity" section and whose OpenID Connect configuration discovered includes the OIDC "userinfo_endpoint" claim.
	IdentitySource string `json:"identitySource"`
}

// User-Managed Access (UMA) source of resource data.
type Metadata_UMA struct {
	// The endpoint of the UMA server.
	// The value must coincide with the "issuer" claim of the UMA config discovered from the well-known uma configuration endpoint.
	Endpoint string `json:"endpoint"`

	// Reference to a Kubernetes secret in the same namespace, that stores client credentials to the resource registration API of the UMA server.
	Credentials *k8score.LocalObjectReference `json:"credentialsRef"`
}

// +kubebuilder:validation:Enum:=GET;POST
type GenericHTTP_Method string

// +kubebuilder:validation:Enum:=application/x-www-form-urlencoded;application/json
type Metadata_GenericHTTP_ContentType string

// Generic HTTP interface to obtain authorization metadata from a HTTP service.
type Metadata_GenericHTTP struct {
	// Endpoint of the HTTP service.
	// The endpoint accepts variable placeholders in the format "{selector}", where "selector" is any pattern supported
	// by https://pkg.go.dev/github.com/tidwall/gjson and selects value from the authorization JSON.
	// E.g. https://ext-auth-server.io/metadata?p={context.request.http.path}
	Endpoint string `json:"endpoint"`

	// HTTP verb used in the request to the service. Accepted values: GET (default), POST.
	// When the request method is POST, the authorization JSON is passed in the body of the request.
	// +kubebuilder:default:=GET
	Method *GenericHTTP_Method `json:"method,omitempty"`

	// Raw body of the HTTP request.
	// Supersedes 'bodyParameters'; use either one or the other.
	// Use it with method=POST; for GET requests, set parameters as query string in the 'endpoint' (placeholders can be used).
	Body *StaticOrDynamicValue `json:"body,omitempty"`

	// Custom parameters to encode in the body of the HTTP request.
	// Superseded by 'body'; use either one or the other.
	// Use it with method=POST; for GET requests, set parameters as query string in the 'endpoint' (placeholders can be used).
	Parameters []JsonProperty `json:"bodyParameters,omitempty"`

	// Content-Type of the request body. Shapes how 'bodyParameters' are encoded.
	// Use it with method=POST; for GET requests, Content-Type is automatically set to 'text/plain'.
	// +kubebuilder:default:=application/x-www-form-urlencoded
	ContentType Metadata_GenericHTTP_ContentType `json:"contentType,omitempty"`

	// Custom headers in the HTTP request.
	Headers []JsonProperty `json:"headers,omitempty"`

	// Reference to a Secret key whose value will be passed by Authorino in the request.
	// The HTTP service can use the shared secret to authenticate the origin of the request.
	// Ignored if used together with oauth2.
	SharedSecret *SecretKeyReference `json:"sharedSecretRef,omitempty"`

	// Authentication with the HTTP service by OAuth2 Client Credentials grant.
	OAuth2 *OAuth2ClientAuthentication `json:"oauth2,omitempty"`

	// Defines where client credentials will be passed in the request to the service.
	// If omitted, it defaults to client credentials passed in the HTTP Authorization header and the "Bearer" prefix expected prepended to the secret value.
	Credentials Credentials `json:"credentials,omitempty"`
}

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

// Authorization policy to be enforced.
// Apart from "name", one of the following parameters is required and only one of the following parameters is allowed: "opa", "json" or "kubernetes".
type Authorization struct {
	// Name of the authorization policy.
	// It can be used to refer to the resolved authorization object in other configs.
	Name string `json:"name"`

	// Priority group of the config.
	// All configs in the same priority group are evaluated concurrently; consecutive priority groups are evaluated sequentially.
	// +kubebuilder:default:=0
	Priority int `json:"priority,omitempty"`

	// Whether this authorization config should generate individual observability metrics
	// +kubebuilder:default:=false
	Metrics bool `json:"metrics,omitempty"`

	// Conditions for Authorino to enforce this authorization policy.
	// If omitted, the config will be enforced for all requests.
	// If present, all conditions must match for the config to be enforced; otherwise, the config will be skipped.
	Conditions []JSONPattern `json:"when,omitempty"`

	// Caching options for the policy evaluation results when enforcing this config.
	// Omit it to avoid caching policy evaluation results for this config.
	Cache *EvaluatorCaching `json:"cache,omitempty"`

	OPA             *Authorization_OPA                 `json:"opa,omitempty"`
	JSON            *Authorization_JSONPatternMatching `json:"json,omitempty"`
	KubernetesAuthz *Authorization_KubernetesAuthz     `json:"kubernetes,omitempty"`
	Authzed         *Authorization_Authzed             `json:"authzed,omitempty"`
}

func (a *Authorization) GetType() string {
	if a.OPA != nil {
		return AuthorizationOPA
	} else if a.JSON != nil {
		return AuthorizationJSONPatternMatching
	} else if a.KubernetesAuthz != nil {
		return AuthorizationKubernetesAuthz
	} else if a.Authzed != nil {
		return AuthorizationAuthzed
	}
	return TypeUnknown
}

// ExternalRegistry specifies external source of data (i.e. OPA policy registry)
type ExternalRegistry struct {
	// Endpoint of the HTTP external registry.
	// The endpoint must respond with either plain/text or application/json content-type.
	// In the latter case, the JSON returned in the body must include a path `result.raw`, where the raw Rego policy will be extracted from. This complies with the specification of the OPA REST API (https://www.openpolicyagent.org/docs/latest/rest-api/#get-a-policy).
	Endpoint string `json:"endpoint,omitempty"`

	// Reference to a Secret key whose value will be passed by Authorino in the request.
	// The HTTP service can use the shared secret to authenticate the origin of the request.
	SharedSecret *SecretKeyReference `json:"sharedSecretRef,omitempty"`

	// Defines where client credentials will be passed in the request to the service.
	// If omitted, it defaults to client credentials passed in the HTTP Authorization header and the "Bearer" prefix expected prepended to the secret value.
	Credentials Credentials `json:"credentials,omitempty"`

	// Duration (in seconds) of the external data in the cache before pulled again from the source.
	TTL int `json:"ttl,omitempty"`
}

// Open Policy Agent (OPA) authorization policy.
type Authorization_OPA struct {
	// Authorization policy as a Rego language document.
	// The Rego document must include the "allow" condition, set by Authorino to "false" by default (i.e. requests are unauthorized unless changed).
	// The Rego document must NOT include the "package" declaration in line 1.
	InlineRego string `json:"inlineRego,omitempty"`

	// External registry of OPA policies.
	ExternalRegistry ExternalRegistry `json:"externalRegistry,omitempty"`

	// Returns the value of all Rego rules in the virtual document. Values can be read in subsequent evaluators/phases of the Auth Pipeline.
	// Otherwise, only the default `allow` rule will be exposed.
	// Returning all Rego rules can affect performance of OPA policies during reconciliation (policy precompile) and at runtime.
	// +kubebuilder:default:=false
	AllValues bool `json:"allValues,omitempty"`
}

// JSON pattern matching authorization policy.
type Authorization_JSONPatternMatching struct {
	// The rules that must all evaluate to "true" for the request to be authorized.
	Rules []JSONPattern `json:"rules"`
}

type Authorization_KubernetesAuthz_ResourceAttributes struct {
	Namespace   StaticOrDynamicValue `json:"namespace,omitempty"`
	Group       StaticOrDynamicValue `json:"group,omitempty"`
	Resource    StaticOrDynamicValue `json:"resource,omitempty"`
	Name        StaticOrDynamicValue `json:"name,omitempty"`
	SubResource StaticOrDynamicValue `json:"subresource,omitempty"`
	Verb        StaticOrDynamicValue `json:"verb,omitempty"`
}

// Kubernetes authorization policy based on `SubjectAccessReview`
// Path and Verb are inferred from the request.
type Authorization_KubernetesAuthz struct {
	// User to test for.
	// If without "Groups", then is it interpreted as "What if User were not a member of any groups"
	User StaticOrDynamicValue `json:"user"`

	// Groups to test for.
	Groups []string `json:"groups,omitempty"`

	// Use ResourceAttributes for checking permissions on Kubernetes resources
	// If omitted, it performs a non-resource `SubjectAccessReview`, with verb and path inferred from the request.
	ResourceAttributes *Authorization_KubernetesAuthz_ResourceAttributes `json:"resourceAttributes,omitempty"`
}

// Authzed authorization
type Authorization_Authzed struct {
	// Endpoint of the Authzed service.
	Endpoint string `json:"endpoint"`

	// Insecure HTTP connection (i.e. disables TLS verification)
	Insecure bool `json:"insecure,omitempty"`

	// Reference to a Secret key whose value will be used by Authorino to authenticate with the Authzed service.
	SharedSecret *SecretKeyReference `json:"sharedSecretRef,omitempty"`

	// The subject that will be checked for the permission or relation.
	Subject *AuthzedObject `json:"subject,omitempty"`
	// The resource on which to check the permission or relation.
	Resource *AuthzedObject `json:"resource,omitempty"`
	// The name of the permission (or relation) on which to execute the check.
	Permission StaticOrDynamicValue `json:"permission,omitempty"`
}

type AuthzedObject struct {
	Name StaticOrDynamicValue `json:"name,omitempty"`
	Kind StaticOrDynamicValue `json:"kind,omitempty"`
}

// +kubebuilder:validation:Enum:=httpHeader;envoyDynamicMetadata
type Response_Wrapper string

// Dynamic response to return to the client.
// Apart from "name", one of the following parameters is required and only one of the following parameters is allowed: "wristband" or "json".
type Response struct {
	// Name of the custom response.
	// It can be used to refer to the resolved response object in other configs.
	Name string `json:"name"`

	// Priority group of the config.
	// All configs in the same priority group are evaluated concurrently; consecutive priority groups are evaluated sequentially.
	// +kubebuilder:default:=0
	Priority int `json:"priority,omitempty"`

	// Whether this response config should generate individual observability metrics
	// +kubebuilder:default:=false
	Metrics bool `json:"metrics,omitempty"`

	// Conditions for Authorino to enforce this custom response config.
	// If omitted, the config will be enforced for all requests.
	// If present, all conditions must match for the config to be enforced; otherwise, the config will be skipped.
	Conditions []JSONPattern `json:"when,omitempty"`

	// Caching options for dynamic responses built when applying this config.
	// Omit it to avoid caching dynamic responses for this config.
	Cache *EvaluatorCaching `json:"cache,omitempty"`

	// How Authorino wraps the response.
	// Use "httpHeader" (default) to wrap the response in an HTTP header; or "envoyDynamicMetadata" to wrap the response as Envoy Dynamic Metadata
	// +kubebuilder:default:=httpHeader
	Wrapper Response_Wrapper `json:"wrapper,omitempty"`
	// The name of key used in the wrapped response (name of the HTTP header or property of the Envoy Dynamic Metadata JSON).
	// If omitted, it will be set to the name of the configuration.
	WrapperKey string `json:"wrapperKey,omitempty"`

	Wristband *Response_Wristband   `json:"wristband,omitempty"`
	JSON      *Response_DynamicJSON `json:"json,omitempty"`
}

func (r *Response) GetType() string {
	if r.Wristband != nil {
		return ResponseWristband
	} else if r.JSON != nil {
		return ResponseDynamicJSON
	}
	return TypeUnknown
}

// Endpoints to callback at the end of each auth pipeline.
type Callback struct {
	// Name of the callback.
	// It can be used to refer to the resolved callback response in other configs.
	Name string `json:"name"`

	// Priority group of the config.
	// All configs in the same priority group are evaluated concurrently; consecutive priority groups are evaluated sequentially.
	// +kubebuilder:default:=0
	Priority int `json:"priority,omitempty"`

	// Whether this callback config should generate individual observability metrics
	// +kubebuilder:default:=false
	Metrics bool `json:"metrics,omitempty"`

	// Conditions for Authorino to perform this callback.
	// If omitted, the callback will be attempted for all requests.
	// If present, all conditions must match for the callback to be attempted; otherwise, the callback will be skipped.
	Conditions []JSONPattern `json:"when,omitempty"`

	HTTP *Metadata_GenericHTTP `json:"http"` // make this 'omitempty' if other alternate methods are added
}

func (r *Callback) GetType() string {
	if r.HTTP != nil {
		return CallbackHTTP
	}
	return TypeUnknown
}

// +kubebuilder:validation:Enum:=ES256;ES384;ES512;RS256;RS384;RS512
type SigningKeyAlgorithm string

type SigningKeyRef struct {
	// Name of the signing key.
	// The value is used to reference the Kubernetes secret that stores the key and in the `kid` claim of the wristband token header.
	Name string `json:"name"`

	// Algorithm to sign the wristband token using the signing key provided
	Algorithm SigningKeyAlgorithm `json:"algorithm"`
}

type Response_Wristband struct {
	// The endpoint to the Authorino service that issues the wristband (format: <scheme>://<host>:<port>/<realm>, where <realm> = <namespace>/<authorino-auth-config-resource-name/wristband-config-name)
	Issuer string `json:"issuer"`
	// Any claims to be added to the wristband token apart from the standard JWT claims (iss, iat, exp) added by default.
	CustomClaims []JsonProperty `json:"customClaims,omitempty"`
	// Time span of the wristband token, in seconds.
	TokenDuration *int64 `json:"tokenDuration,omitempty"`
	// Reference by name to Kubernetes secrets and corresponding signing algorithms.
	// The secrets must contain a `key.pem` entry whose value is the signing key formatted as PEM.
	SigningKeyRefs []*SigningKeyRef `json:"signingKeyRefs"`
}

type Response_DynamicJSON struct {
	// List of JSON property-value pairs to be added to the dynamic response.
	Properties []JsonProperty `json:"properties"`
}

// +kubebuilder:validation:Minimum:=300
// +kubebuilder:validation:Maximum:=599
type DenyWith_Code int64

type DenyWithSpec struct {
	// HTTP status code to override the default denial status code.
	Code DenyWith_Code `json:"code,omitempty"`

	// HTTP message to override the default denial message.
	Message *StaticOrDynamicValue `json:"message,omitempty"`

	// HTTP response headers to override the default denial headers.
	Headers []JsonProperty `json:"headers,omitempty"`

	// HTTP response body to override the default denial body.
	Body *StaticOrDynamicValue `json:"body,omitempty"`
}

type DenyWith struct {
	// Denial status customization when the request is unauthenticated.
	Unauthenticated *DenyWithSpec `json:"unauthenticated,omitempty"`

	// Denial status customization when the request is unauthorized.
	Unauthorized *DenyWithSpec `json:"unauthorized,omitempty"`
}

type ConditionType string

type Condition struct {
	// Type of condition
	Type ConditionType `json:"type"`

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

type Summary struct {
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

// AuthConfigStatus defines the observed state of AuthConfig
type AuthConfigStatus struct {
	Conditions []Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
	Summary    Summary     `json:"summary,omitempty"`
}

func (s *AuthConfigStatus) Ready() bool {
	for _, condition := range s.Conditions {
		if condition.Type == StatusConditionReady {
			return condition.Status == k8score.ConditionTrue
		}
	}
	return false
}

// AuthConfig is the schema for Authorino's AuthConfig API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
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

// +kubebuilder:object:root=true

// AuthConfigList contains a list of AuthConfig
type AuthConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           AuthConfigSlice `json:"items"`
}

type AuthConfigSlice []AuthConfig

func (s AuthConfigSlice) Len() int {
	return len(s)
}

func (s AuthConfigSlice) Less(i, j int) bool {
	return s[i].CreationTimestamp.Before(&s[j].CreationTimestamp)
}

func (s AuthConfigSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func init() {
	SchemeBuilder.Register(&AuthConfig{}, &AuthConfigList{})
}
