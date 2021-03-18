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
	IdentityOidc                     = "IDENTITY_OIDC"
	IdentityApiKey                   = "IDENTITY_APIKEY"
	MetadataUma                      = "METADATA_UMA"
	MetadataUserinfo                 = "METADATA_USERINFO"
	AuthorizationOPA                 = "AUTHORIZATION_OPA"
	AuthorizationJSONPatternMatching = "AUTHORIZATION_JSON"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ServiceSpec defines the desired state of Service
type ServiceSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	Hosts         []string         `json:"hosts"`
	Identity      []*Identity      `json:"identity,omitempty"`
	Metadata      []*Metadata      `json:"metadata,omitempty"`
	Authorization []*Authorization `json:"authorization,omitempty"`
}

type Credentials struct {
	In          string `json:"in"`
	KeySelector string `json:"key_selector"`
}

type Identity struct {
	// Adding a Name as we need to reference it from the metadata section.
	Name        string               `json:"name"`
	Credentials Credentials          `json:"credentials,omitempty"`
	Oidc        *Identity_OidcConfig `json:"oidc,omitempty"`
	APIKey      *Identity_APIKey     `json:"api_key,omitempty"`
}

type Identity_OidcConfig struct {
	Endpoint string `json:"endpoint"`
}

type Identity_APIKey struct {
	LabelSelectors map[string]string `json:"label_selectors"`
}

type Metadata struct {
	Name     string             `json:"name"`
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

// Metadata_UserInfo & Metadata_UMA are the same right now, I'm keeping them split
// just in case I'm missing something, but we can merge them into a single type if they don't
// really require any extra field...
type Metadata_UserInfo struct {
	IdentitySource string `json:"identitySource"`
}
type Metadata_UMA struct {
	IdentitySource string                   `json:"identitySource"`
	Credentials    *v1.LocalObjectReference `json:"credentialsRef,omitempty"`
}

type Authorization struct {
	Name string                             `json:"name"`
	OPA  *Authorization_OPA                 `json:"opa,omitempty"`
	JSON *Authorization_JSONPatternMatching `json:"json,omitempty"`
}

type Authorization_OPA struct {
	InlineRego string `json:"inlineRego,omitempty"`
}

type Authorization_JSONPatternMatching struct {
	Rules []Authorization_JSONPatternMatching_Rule `json:"rules,omitempty"`
}

type Authorization_JSONPatternMatching_Rule struct {
	Selector string `json:"selector"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
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

// Service is the Schema for the services API
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
	if i.Oidc != nil {
		return IdentityOidc
	} else if i.APIKey != nil {
		return IdentityApiKey
	}
	return TypeUnknown
}

func init() {
	SchemeBuilder.Register(&Service{}, &ServiceList{})
}
