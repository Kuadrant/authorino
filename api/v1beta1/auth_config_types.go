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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	TypeUnknown                      = "UNKNOWN"
	IdentityOAuth2                   = "IDENTITY_OAUTH2"
	IdentityOidc                     = "IDENTITY_OIDC"
	IdentityApiKey                   = "IDENTITY_APIKEY"
	IdentityKubernetesAuth           = "IDENTITY_KUBERNETESAUTH"
	MetadataUma                      = "METADATA_UMA"
	MetadataGenericHTTP              = "METADATA_GENERIC_HTTP"
	MetadataUserinfo                 = "METADATA_USERINFO"
	AuthorizationOPA                 = "AUTHORIZATION_OPA"
	AuthorizationJSONPatternMatching = "AUTHORIZATION_JSON"
	AuthorizationKubernetesAuthz     = "AUTHORIZATION_KUBERNETESAUTHZ"
	ResponseWristband                = "RESPONSE_WRISTBAND"
	ResponseDynamicJSON              = "RESPONSE_DYNAMIC_JSON"
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

// Specifies the desired state of the AuthConfig resource, i.e. the authencation/authorization scheme to be applied to protect the matching service hosts.
type AuthConfigSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// The list of public host names of the services protected by this authentication/authorization scheme.
	// Authorino uses the requested host to lookup for the corresponding authentication/authorization configs to enforce.
	Hosts []string `json:"hosts"`

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

	// Custom denial response codes, statuses and headers to override default 40x's.
	DenyWith *DenyWith `json:"denyWith,omitempty"`
}

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
	// It may as well be used for this identity config to be referred in some metadata configs.
	Name string `json:"name"`

	// Defines where client credentials are required to be passed in the request for this identity source/authentication mode.
	// If omitted, it defaults to client credentials passed in the HTTP Authorization header and the "Bearer" prefix expected prepended to the credentials value (token, API key, etc).
	Credentials Credentials `json:"credentials,omitempty"`

	// Extends the resolved identity object with additional custom properties before appending to the authorization JSON.
	// It requires the resolved identity object to always be of the JSON type 'object'. Other JSON types (array, string, etc) will break.
	ExtendedProperties []JsonProperty `json:"extendedProperties,omitempty"`

	OAuth2         *Identity_OAuth2Config   `json:"oauth2,omitempty"`
	Oidc           *Identity_OidcConfig     `json:"oidc,omitempty"`
	APIKey         *Identity_APIKey         `json:"apiKey,omitempty"`
	KubernetesAuth *Identity_KubernetesAuth `json:"kubernetes,omitempty"`
}

func (i *Identity) GetType() string {
	if i.OAuth2 != nil {
		return IdentityOAuth2
	} else if i.Oidc != nil {
		return IdentityOidc
	} else if i.APIKey != nil {
		return IdentityApiKey
	} else if i.KubernetesAuth != nil {
		return IdentityKubernetesAuth
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
	Credentials *v1.LocalObjectReference `json:"credentialsRef"`
}

type Identity_OidcConfig struct {
	// Endpoint of the OIDC issuer.
	// Authorino will append to this value the well-known path to the OpenID Connect discovery endpoint (i.e. "/.well-known/openid-configuration"), used to automatically discover the OpenID Connect configuration, whose set of claims is expected to include (among others) the "jkws_uri" claim.
	// The value must coincide with the value of  the "iss" (issuer) claim of the discovered OpenID Connect configuration.
	Endpoint string `json:"endpoint"`
}

type Identity_APIKey struct {
	// The map of label selectors used by Authorino to match secrets from the cluster storing valid credentials to authenticate to this service
	LabelSelectors map[string]string `json:"labelSelectors"`
}

type Identity_KubernetesAuth struct {
	// The list of audiences (scopes) that must be claimed in a Kubernetes authentication token supplied in the request, and reviewed by Authorino.
	// If omitted, Authorino will review tokens expecting the host name of the requested protected service amongst the audiences.
	Audiences []string `json:"audiences,omitempty"`
}

// The metadata config.
// Apart from "name", one of the following parameters is required and only one of the following parameters is allowed: "userInfo" or "uma".
type Metadata struct {
	// The name of the metadata source.
	// Policies of te authorization phase can refer to this metadata by this value.
	Name string `json:"name"`

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
	Credentials *v1.LocalObjectReference `json:"credentialsRef"`
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
	Method GenericHTTP_Method `json:"method,omitempty"`

	// Custom parameters to encode in the body of the HTTP request.
	// Use it with method=POST; for GET requests, specify parameters using placeholders in the endpoint.
	Parameters []JsonProperty `json:"bodyParameters,omitempty"`

	// Content-Type of the request body.
	// +kubebuilder:default:=application/x-www-form-urlencoded
	ContentType Metadata_GenericHTTP_ContentType `json:"contentType,omitempty"`

	// Reference to a Secret key whose value will be passed by Authorino in the request.
	// The HTTP service can use the shared secret to authenticate the origin of the request.
	SharedSecret *SecretKeyReference `json:"sharedSecretRef,omitempty"`

	// Defines where client credentials will be passed in the request to the service.
	// If omitted, it defaults to client credentials passed in the HTTP Authorization header and the "Bearer" prefix expected prepended to the secret value.
	Credentials Credentials `json:"credentials,omitempty"`
}

// Authorization policy to be enforced.
// Apart from "name", one of the following parameters is required and only one of the following parameters is allowed: "opa", "json" or "kubernetes".
type Authorization struct {
	// Name of the authorization policy.
	Name string `json:"name"`

	OPA             *Authorization_OPA                 `json:"opa,omitempty"`
	JSON            *Authorization_JSONPatternMatching `json:"json,omitempty"`
	KubernetesAuthz *Authorization_KubernetesAuthz     `json:"kubernetes,omitempty"`
}

func (a *Authorization) GetType() string {
	if a.OPA != nil {
		return AuthorizationOPA
	} else if a.JSON != nil {
		return AuthorizationJSONPatternMatching
	} else if a.KubernetesAuthz != nil {
		return AuthorizationKubernetesAuthz
	}
	return TypeUnknown
}

//ExternalRegistry specifies external source of data (i.e. OPA policy registry)
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
}

// Open Policy Agent (OPA) authorization policy.
type Authorization_OPA struct {
	// Authorization policy as a Rego language document.
	// The Rego document must include the "allow" condition, set by Authorino to "false" by default (i.e. requests are unauthorized unless changed).
	// The Rego document must NOT include the "package" declaration in line 1.
	InlineRego string `json:"inlineRego,omitempty"`

	// External registry of OPA policies.
	ExternalRegistry ExternalRegistry `json:"externalRegistry,omitempty"`
}

// JSON pattern matching authorization policy.
type Authorization_JSONPatternMatching struct {
	// Conditions that must match for Authorino to enforce this policy; otherwise, the policy will be skipped.
	Conditions []Authorization_JSONPatternMatching_Rule `json:"conditions,omitempty"`

	// The rules that must all evaluate to "true" for the request to be authorized.
	Rules []Authorization_JSONPatternMatching_Rule `json:"rules,omitempty"`
}

// +kubebuilder:validation:Enum:=eq;neq;incl;excl;matches
type JSONPatternMatching_Rule_Operator string

type Authorization_JSONPatternMatching_Rule struct {
	// Any pattern supported by https://pkg.go.dev/github.com/tidwall/gjson.
	// The value is used to fetch content from the input authorization JSON built by Authorino along the identity and metadata phases.
	Selector string `json:"selector"`
	// The binary operator to be applied to the content fetched from the authorization JSON, for comparison with "value".
	// Possible values are: "eq" (equal to), "neq" (not equal to), "incl" (includes; for arrays), "excl" (excludes; for arrays), "matches" (regex)
	Operator JSONPatternMatching_Rule_Operator `json:"operator"`
	// The value of reference for the comparison with the content fetched from the authorization policy.
	// If used with the "matches" operator, the value must compile to a valid Golang regex.
	Value string `json:"value"`
}

type Authorization_KubernetesAuthz_Attribute struct {
	Value     string            `json:"value,omitempty"`
	ValueFrom ValueFromAuthJSON `json:"valueFrom,omitempty"`
}

type Authorization_KubernetesAuthz_ResourceAttributes struct {
	Namespace   Authorization_KubernetesAuthz_Attribute `json:"namespace,omitempty"`
	Group       Authorization_KubernetesAuthz_Attribute `json:"group,omitempty"`
	Resource    Authorization_KubernetesAuthz_Attribute `json:"resource,omitempty"`
	Name        Authorization_KubernetesAuthz_Attribute `json:"name,omitempty"`
	SubResource Authorization_KubernetesAuthz_Attribute `json:"subresource,omitempty"`
	Verb        Authorization_KubernetesAuthz_Attribute `json:"verb,omitempty"`
}

// Kubernetes authorization policy based on `SubjectAccessReview`
// Path and Verb are inferred from the request.
type Authorization_KubernetesAuthz struct {
	// Conditions that must match for Authorino to enforce this policy; otherwise, the policy will be skipped.
	Conditions []Authorization_JSONPatternMatching_Rule `json:"conditions,omitempty"`

	// User to test for.
	// If without "Groups", then is it interpreted as "What if User were not a member of any groups"
	User Authorization_KubernetesAuthz_Attribute `json:"user"`

	// Groups to test for.
	Groups []string `json:"groups,omitempty"`

	// Use ResourceAttributes for checking permissions on Kubernetes resources
	// If omitted, it performs a non-resource `SubjectAccessReview`, with verb and path inferred from the request.
	ResourceAttributes *Authorization_KubernetesAuthz_ResourceAttributes `json:"resourceAttributes,omitempty"`
}

// +kubebuilder:validation:Enum:=httpHeader;envoyDynamicMetadata
type Response_Wrapper string

// Dynamic response to return to the client.
// Apart from "name", one of the following parameters is required and only one of the following parameters is allowed: "wristband" or "json".
type Response struct {
	// Name of the custom response.
	Name string `json:"name"`
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

// +kubebuilder:validation:Enum:=ES256;ES384;ES512;RS256;RS384;RS512
type SigningKeyAlgorithm string

type SigningKeyRef struct {
	// Name of the signing key.
	// The value is used to reference the Kubernetes secret that stores the key and in the `kid` claim of the wristband token header.
	Name string `json:"name"`

	// Algorithm to sign the wristband token using the signing key provided
	Algorithm SigningKeyAlgorithm `json:"algorithm"`
}

type ValueFromAuthJSON struct {
	// Selector to fill the value from the authorization JSON.
	// Any patterns supported by https://pkg.go.dev/github.com/tidwall/gjson can be used.
	// The value can be just the pattern with the path to fetch from the authorization JSON (e.g. 'context.request.http.host')
	// or a string template with variable placeholders that resolve to patterns (e.g. "Hello, {auth.identity.name}!")
	// The following string modifiers are available: @extract:{sep:" ",pos:0}, @replace{old:"",new:""}, @case:upper|lower,
	// and @base64:encode|decode.
	AuthJSON string `json:"authJSON,omitempty"`
}

type JsonProperty struct {
	// The name of the claim
	Name string `json:"name"`
	// Static value of the claim
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Value runtime.RawExtension `json:"value,omitempty"`
	// Dynamic value of the claim
	ValueFrom ValueFromAuthJSON `json:"valueFrom,omitempty"`
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
	Message string `json:"message,omitempty"`

	// HTTP response headers to override the default denial headers.
	Headers []JsonProperty `json:"headers,omitempty"`
}

type DenyWith struct {
	// Denial status customization when the request is unauthenticated.
	Unauthenticated *DenyWithSpec `json:"unauthenticated,omitempty"`

	// Denial status customization when the request is unauthorized.
	Unauthorized *DenyWithSpec `json:"unauthorized,omitempty"`
}

// AuthConfigStatus defines the observed state of AuthConfig
type AuthConfigStatus struct {
	Ready                    bool  `json:"ready"`
	NumIdentitySources       int64 `json:"numIdentitySources"`
	NumMetadataSources       int64 `json:"numMetadataSources"`
	NumAuthorizationPolicies int64 `json:"numAuthorizationPolicies"`
	NumResponseItems         int64 `json:"numResponseItems"`
	FestivalWristbandEnabled bool  `json:"festivalWristbandEnabled"`
}

// AuthConfig is the schema for Authorino's AuthConfig API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`,description="Ready?"
// +kubebuilder:printcolumn:name="Id sources",type=integer,JSONPath=`.status.numIdentitySources`,description="Number of trusted identity sources",priority=2
// +kubebuilder:printcolumn:name="Metadata sources",type=integer,JSONPath=`.status.numMetadataSources`,description="Number of external metadata sources",priority=2
// +kubebuilder:printcolumn:name="Authz policies",type=integer,JSONPath=`.status.numAuthorizationPolicies`,description="Number of authorization policies",priority=2
// +kubebuilder:printcolumn:name="Response items",type=integer,JSONPath=`.status.numResponseItems`,description="Number of items added to the client response",priority=2
// +kubebuilder:printcolumn:name="Wristband",type=boolean,JSONPath=`.status.festivalWristbandEnabled`,description="Whether issuing Festival Wristbands",priority=2
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
	Items           []AuthConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AuthConfig{}, &AuthConfigList{})
}
