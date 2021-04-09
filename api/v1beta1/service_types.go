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
)

const (
	TypeUnknown                      = "UNKNOWN"
	IdentityOAuth2                   = "IDENTITY_OAUTH2"
	IdentityOidc                     = "IDENTITY_OIDC"
	IdentityApiKey                   = "IDENTITY_APIKEY"
	IdentityKubernetesAuth           = "IDENTITY_KUBERNETESAUTH"
	MetadataUma                      = "METADATA_UMA"
	MetadataUserinfo                 = "METADATA_USERINFO"
	AuthorizationOPA                 = "AUTHORIZATION_OPA"
	AuthorizationJSONPatternMatching = "AUTHORIZATION_JSON"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// Specifies the desired state of the Service resource, i.e. the authencation/authorization scheme to be applied to protect the matching HTTP services.
type ServiceSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// The list of public host names of the HTTP services protected by this authentication/authorization scheme.
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

	OAuth2         *Identity_OAuth2Config   `json:"oauth2,omitempty"`
	Oidc           *Identity_OidcConfig     `json:"oidc,omitempty"`
	APIKey         *Identity_APIKey         `json:"apiKey,omitempty"`
	KubernetesAuth *Identity_KubernetesAuth `json:"kubernetes,omitempty"`
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

	UserInfo *Metadata_UserInfo `json:"userInfo,omitempty"`
	UMA      *Metadata_UMA      `json:"uma,omitempty"`
}

func (m *Metadata) GetType() string {
	if m.UserInfo != nil {
		return MetadataUserinfo
	} else if m.UMA != nil {
		return MetadataUma
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

// Authorization policy to be enforced.
// Apart from "name", one of the following parameters is required and only one of the following parameters is allowed: "opa" or "json".
type Authorization struct {
	// Name of the authorization policy.
	Name string `json:"name"`

	OPA  *Authorization_OPA                 `json:"opa,omitempty"`
	JSON *Authorization_JSONPatternMatching `json:"json,omitempty"`
}

// Open Policy Agent (OPA) authorization policy.
type Authorization_OPA struct {
	// Authorization policy as a Rego language document.
	// The Rego document must include the "allow" condition, set by Authorino to "false" by default (i.e. requests are unauthorized unless changed).
	// The Rego document must NOT include the "package" declaration in line 1.
	InlineRego string `json:"inlineRego,omitempty"`
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

func (a *Authorization) GetType() string {
	if a.OPA != nil {
		return AuthorizationOPA
	} else if a.JSON != nil {
		return AuthorizationJSONPatternMatching
	}
	return TypeUnknown
}

// ServiceStatus defines the observed state of Service
type ServiceStatus struct {
	Ready bool `json:"ready"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Service is the schema for Authorino's services API
type Service struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceSpec   `json:"spec,omitempty"`
	Status ServiceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ServiceList contains a list of Service
type ServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Service `json:"items"`
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

func init() {
	SchemeBuilder.Register(&Service{}, &ServiceList{})
}
