/*
Copyright 2026 Red Hat, Inc.

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

package v1beta3_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kuadrant/authorino/api/v1beta3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

type validationTestCase struct {
	desc       string
	mutate     func(ac *v1beta3.AuthConfig)
	wantErrors []string
}

func runTests(t *testing.T, namePrefix string, baseAuthConfig v1beta3.AuthConfig, testCases []validationTestCase) {
	t.Helper()
	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ac := baseAuthConfig.DeepCopy()
			// Unique name for each test case to avoid conflicts
			ac.Name = fmt.Sprintf("%s-%v", namePrefix, time.Now().UnixNano())

			if tc.mutate != nil {
				tc.mutate(ac)
			}

			err := k8sClient.Create(ctx, ac)

			// Check if error expectation matches
			if (len(tc.wantErrors) != 0) != (err != nil) {
				t.Fatalf("Unexpected response while creating AuthConfig; got err=\n%v\n;want error=%v", err, tc.wantErrors != nil)
			}

			// If we expect errors, verify the error message contains expected strings
			if err != nil {
				var missingErrorStrings []string
				for _, wantError := range tc.wantErrors {
					if !celErrorStringMatches(err.Error(), wantError) {
						missingErrorStrings = append(missingErrorStrings, wantError)
					}
				}
				if len(missingErrorStrings) != 0 {
					t.Errorf("Unexpected response while creating AuthConfig; got err=\n%v\n;missing strings within error=%q", err, missingErrorStrings)
				}
			} else {
				// Cleanup successful creations
				_ = k8sClient.Delete(ctx, ac)
			}
		})
	}
}

// TestKubernetesSubjectAccessReviewCELValidation tests the CEL validation rules
// for the kubernetesSubjectAccessReview authorization configuration.
//
// The validation rules are:
//  1. At least one of user, groups, or authorizationGroups must be specified:
//     has(self.user) || has(self.groups) || has(self.authorizationGroups)
//  2. If groups is specified, it must not be empty:
//     has(self.groups) ? size(self.groups) > 0 : true
func TestKubernetesSubjectAccessReviewCELValidation(t *testing.T) {
	// Base valid AuthConfig with kubernetesSubjectAccessReview authorization
	baseAuthConfig := v1beta3.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1beta3.AuthConfigSpec{
			Hosts: []string{"test.example.com"},
			Authentication: map[string]v1beta3.AuthenticationSpec{
				"api-key": {
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						Plain: &v1beta3.PlainIdentitySpec{
							Selector: "context.request.http.headers.x-user-name",
						},
					},
				},
			},
			Authorization: map[string]v1beta3.AuthorizationSpec{
				"k8s-sar": {
					AuthorizationMethodSpec: v1beta3.AuthorizationMethodSpec{
						KubernetesSubjectAccessReview: &v1beta3.KubernetesSubjectAccessReviewAuthorizationSpec{
							User: &v1beta3.ValueOrSelector{
								Selector: "auth.identity.username",
							},
							ResourceAttributes: &v1beta3.KubernetesSubjectAccessReviewResourceAttributesSpec{
								Namespace: v1beta3.ValueOrSelector{Value: runtime.RawExtension{Raw: []byte(`"default"`)}},
								Verb:      v1beta3.ValueOrSelector{Value: runtime.RawExtension{Raw: []byte(`"get"`)}},
								Resource:  v1beta3.ValueOrSelector{Value: runtime.RawExtension{Raw: []byte(`"secrets"`)}},
							},
						},
					},
				},
			},
		},
	}

	runTests(t, "test-sar", baseAuthConfig, []validationTestCase{
		{
			desc: "valid - user specified",
			mutate: func(ac *v1beta3.AuthConfig) {
				// Default baseAuthConfig already has user specified
			},
		},
		{
			desc: "valid - groups specified (static list)",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.User = nil
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.Groups = []string{
					"system:developers",
					"admin-group",
				}
			},
		},
		{
			desc: "valid - authorizationGroups specified (dynamic)",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.User = nil
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.AuthorizationGroups = &v1beta3.ValueOrSelector{
					Selector: "auth.identity.groups",
				}
			},
		},
		{
			desc: "valid - user and groups specified",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.Groups = []string{
					"system:authenticated",
				}
			},
		},
		{
			desc: "valid - user and authorizationGroups specified",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.AuthorizationGroups = &v1beta3.ValueOrSelector{
					Selector: "auth.identity.groups",
				}
			},
		},
		{
			desc: "valid - all three fields specified",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.Groups = []string{
					"system:authenticated",
				}
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.AuthorizationGroups = &v1beta3.ValueOrSelector{
					Selector: "auth.identity.groups",
				}
			},
		},
		{
			desc: "invalid - no user, groups, or authorizationGroups",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.User = nil
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.Groups = nil
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.AuthorizationGroups = nil
			},
			wantErrors: []string{
				"At least one of user, groups, or authorizationGroups must be specified",
			},
		},
		{
			desc: "invalid - empty groups array (no user or authorizationGroups)",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.User = nil
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.Groups = []string{}
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.AuthorizationGroups = nil
			},
			wantErrors: []string{
				// Note: Empty slices are omitted during JSON marshaling (omitempty tag),
				// so has(self.groups) returns false and the first validation rule fails.
				// The second rule (size check) only triggers when groups is explicitly
				// set to [] in raw YAML/JSON (which we can't easily test via Go client).
				"At least one of user, groups, or authorizationGroups must be specified",
			},
		},
		{
			desc: "valid - user with static value",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.User = &v1beta3.ValueOrSelector{
					Value: runtime.RawExtension{Raw: []byte(`"system:serviceaccount:default:my-sa"`)},
				}
			},
		},
		{
			desc: "valid - user with expression (CEL)",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.User = &v1beta3.ValueOrSelector{
					Expression: "auth.identity.sub",
				}
			},
		},
		{
			desc: "valid - authorizationGroups with static value",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.User = nil
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.AuthorizationGroups = &v1beta3.ValueOrSelector{
					Value: runtime.RawExtension{Raw: []byte(`"system:developers"`)},
				}
			},
		},
		{
			desc: "valid - non-resource SAR with user",
			mutate: func(ac *v1beta3.AuthConfig) {
				// Non-resource SAR (no resourceAttributes)
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.ResourceAttributes = nil
			},
		},
		{
			desc: "invalid - non-resource SAR with no user, groups, or authorizationGroups",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.User = nil
				ac.Spec.Authorization["k8s-sar"].KubernetesSubjectAccessReview.ResourceAttributes = nil
			},
			wantErrors: []string{
				"At least one of user, groups, or authorizationGroups must be specified",
			},
		},
	})

	// Test explicit empty groups array using unstructured to bypass omitempty marshaling
	t.Run("invalid - explicit empty groups array via unstructured (no user or authorizationGroups)", func(t *testing.T) {
		ctx := context.Background()

		// Create an unstructured object with explicit groups: []
		u := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "authorino.kuadrant.io/v1beta3",
				"kind":       "AuthConfig",
				"metadata": map[string]interface{}{
					"name":      fmt.Sprintf("test-sar-%v", time.Now().UnixNano()),
					"namespace": metav1.NamespaceDefault,
				},
				"spec": map[string]interface{}{
					"hosts": []interface{}{"test.example.com"},
					"authentication": map[string]interface{}{
						"api-key": map[string]interface{}{
							"plain": map[string]interface{}{
								"selector": "context.request.http.headers.x-user-name",
							},
						},
					},
					"authorization": map[string]interface{}{
						"k8s-sar": map[string]interface{}{
							"kubernetesSubjectAccessReview": map[string]interface{}{
								"groups": []interface{}{}, // Explicit empty array
								"resourceAttributes": map[string]interface{}{
									"namespace": map[string]interface{}{
										"value": "default",
									},
									"verb": map[string]interface{}{
										"value": "get",
									},
									"resource": map[string]interface{}{
										"value": "secrets",
									},
								},
							},
						},
					},
				},
			},
		}

		err := k8sClient.Create(ctx, u)

		if err == nil {
			t.Fatalf("Expected validation error for explicit empty groups array, but creation succeeded")
		}

		// Should trigger the second validation rule about empty groups
		if !celErrorStringMatches(err.Error(), "'groups' must not be empty") {
			t.Errorf("Expected error containing \"'groups' must not be empty\", got: %v", err)
		}
	})

	// Test explicit empty groups array with user present using unstructured
	t.Run("invalid - explicit empty groups array via unstructured (user specified)", func(t *testing.T) {
		ctx := context.Background()

		u := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "authorino.kuadrant.io/v1beta3",
				"kind":       "AuthConfig",
				"metadata": map[string]interface{}{
					"name":      fmt.Sprintf("test-sar-%v", time.Now().UnixNano()),
					"namespace": metav1.NamespaceDefault,
				},
				"spec": map[string]interface{}{
					"hosts": []interface{}{"test.example.com"},
					"authentication": map[string]interface{}{
						"api-key": map[string]interface{}{
							"plain": map[string]interface{}{
								"selector": "context.request.http.headers.x-user-name",
							},
						},
					},
					"authorization": map[string]interface{}{
						"k8s-sar": map[string]interface{}{
							"kubernetesSubjectAccessReview": map[string]interface{}{
								"user": map[string]interface{}{
									"selector": "auth.identity.username",
								},
								"groups": []interface{}{}, // Explicit empty array (should be invalid even with user)
								"resourceAttributes": map[string]interface{}{
									"namespace": map[string]interface{}{
										"value": "default",
									},
									"verb": map[string]interface{}{
										"value": "get",
									},
									"resource": map[string]interface{}{
										"value": "secrets",
									},
								},
							},
						},
					},
				},
			},
		}

		err := k8sClient.Create(ctx, u)

		if err == nil {
			t.Fatalf("Expected validation error for explicit empty groups array, but creation succeeded")
		}

		if !celErrorStringMatches(err.Error(), "'groups' must not be empty") {
			t.Errorf("Expected error containing \"'groups' must not be empty\", got: %v", err)
		}
	})
}

// TestHttpEndpointSpecCELValidation tests the CEL validation rules on HttpEndpointSpec:
//
//	has(self.url) != has(self.urlExpression) -> "Use exactly one of: url, urlExpression"
//	!has(self.body) || !has(self.bodyParameters) -> "Use one of: body, bodyParameters"
func TestHttpEndpointSpecCELValidation(t *testing.T) {
	baseAuthConfig := v1beta3.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1beta3.AuthConfigSpec{
			Hosts: []string{"test-http.example.com"},
			Authentication: map[string]v1beta3.AuthenticationSpec{
				"anonymous": {
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						AnonymousAccess: &v1beta3.AnonymousAccessSpec{},
					},
				},
			},
			Metadata: map[string]v1beta3.MetadataSpec{
				"ext": {
					MetadataMethodSpec: v1beta3.MetadataMethodSpec{
						Http: &v1beta3.HttpEndpointSpec{
							Url: "http://metadata.example.com",
						},
					},
				},
			},
		},
	}

	runTests(t, "test-http", baseAuthConfig, []validationTestCase{
		{
			desc: "valid - url only",
		},
		{
			desc: "valid - urlExpression only",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Metadata["ext"] = v1beta3.MetadataSpec{
					MetadataMethodSpec: v1beta3.MetadataMethodSpec{
						Http: &v1beta3.HttpEndpointSpec{
							UrlExpression: `"http://metadata.example.com/" + request.path`,
						},
					},
				}
			},
		},
		{
			desc: "invalid - both url and urlExpression",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Metadata["ext"] = v1beta3.MetadataSpec{
					MetadataMethodSpec: v1beta3.MetadataMethodSpec{
						Http: &v1beta3.HttpEndpointSpec{
							Url:           "http://metadata.example.com",
							UrlExpression: `"http://metadata.example.com/" + request.path`,
						},
					},
				}
			},
			wantErrors: []string{"Use exactly one of: url, urlExpression"},
		},
		{
			desc: "invalid - neither url nor urlExpression",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Metadata["ext"] = v1beta3.MetadataSpec{
					MetadataMethodSpec: v1beta3.MetadataMethodSpec{
						Http: &v1beta3.HttpEndpointSpec{},
					},
				}
			},
			wantErrors: []string{"Use exactly one of: url, urlExpression"},
		},
		{
			desc: "valid - body only",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Metadata["ext"] = v1beta3.MetadataSpec{
					MetadataMethodSpec: v1beta3.MetadataMethodSpec{
						Http: &v1beta3.HttpEndpointSpec{
							Url: "http://metadata.example.com",
							Body: &v1beta3.ValueOrSelector{
								Value: runtime.RawExtension{Raw: []byte(`"request body"`)},
							},
						},
					},
				}
			},
		},
		{
			desc: "valid - bodyParameters only",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Metadata["ext"] = v1beta3.MetadataSpec{
					MetadataMethodSpec: v1beta3.MetadataMethodSpec{
						Http: &v1beta3.HttpEndpointSpec{
							Url: "http://metadata.example.com",
							Parameters: v1beta3.NamedValuesOrSelectors{
								"param": {Value: runtime.RawExtension{Raw: []byte(`"value"`)}},
							},
						},
					},
				}
			},
		},
		{
			desc: "invalid - both body and bodyParameters",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Metadata["ext"] = v1beta3.MetadataSpec{
					MetadataMethodSpec: v1beta3.MetadataMethodSpec{
						Http: &v1beta3.HttpEndpointSpec{
							Url: "http://metadata.example.com",
							Body: &v1beta3.ValueOrSelector{
								Value: runtime.RawExtension{Raw: []byte(`"request body"`)},
							},
							Parameters: v1beta3.NamedValuesOrSelectors{
								"param": {Value: runtime.RawExtension{Raw: []byte(`"value"`)}},
							},
						},
					},
				}
			},
			wantErrors: []string{"Use one of: body, bodyParameters"},
		},
	})
}

// TestOpaAuthorizationSpecCELValidation tests the CEL validation rule on OpaAuthorizationSpec:
//
//	has(self.rego) != has(self.externalPolicy) -> "Use exactly one of: rego, externalPolicy"
func TestOpaAuthorizationSpecCELValidation(t *testing.T) {
	baseAuthConfig := v1beta3.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1beta3.AuthConfigSpec{
			Hosts: []string{"test-opa.example.com"},
			Authentication: map[string]v1beta3.AuthenticationSpec{
				"anonymous": {
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						AnonymousAccess: &v1beta3.AnonymousAccessSpec{},
					},
				},
			},
			Authorization: map[string]v1beta3.AuthorizationSpec{
				"opa-policy": {
					AuthorizationMethodSpec: v1beta3.AuthorizationMethodSpec{
						Opa: &v1beta3.OpaAuthorizationSpec{
							Rego: "allow = true",
						},
					},
				},
			},
		},
	}

	runTests(t, "test-opa", baseAuthConfig, []validationTestCase{
		{
			desc: "valid - rego only",
		},
		{
			desc: "valid - externalPolicy only",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["opa-policy"] = v1beta3.AuthorizationSpec{
					AuthorizationMethodSpec: v1beta3.AuthorizationMethodSpec{
						Opa: &v1beta3.OpaAuthorizationSpec{
							External: &v1beta3.ExternalOpaPolicy{
								HttpEndpointSpec: &v1beta3.HttpEndpointSpec{
									Url: "https://opa.example.com/policy.rego",
								},
							},
						},
					},
				}
			},
		},
		{
			desc: "invalid - neither rego nor externalPolicy",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["opa-policy"] = v1beta3.AuthorizationSpec{
					AuthorizationMethodSpec: v1beta3.AuthorizationMethodSpec{
						Opa: &v1beta3.OpaAuthorizationSpec{},
					},
				}
			},
			wantErrors: []string{"Use exactly one of: rego, externalPolicy"},
		},
		{
			desc: "invalid - both rego and externalPolicy",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authorization["opa-policy"] = v1beta3.AuthorizationSpec{
					AuthorizationMethodSpec: v1beta3.AuthorizationMethodSpec{
						Opa: &v1beta3.OpaAuthorizationSpec{
							Rego: "allow = true",
							External: &v1beta3.ExternalOpaPolicy{
								HttpEndpointSpec: &v1beta3.HttpEndpointSpec{
									Url: "https://opa.example.com/policy.rego",
								},
							},
						},
					},
				}
			},
			wantErrors: []string{"Use exactly one of: rego, externalPolicy"},
		},
	})
}

// TestCredentialsMaxPropertiesValidation tests the maxProperties=1 constraint on Credentials.
// This uses OpenAPI maxProperties instead of CEL to stay within the CRD cost budget
func TestCredentialsMaxPropertiesValidation(t *testing.T) {
	baseAuthConfig := v1beta3.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1beta3.AuthConfigSpec{
			Hosts: []string{"test-creds.example.com"},
			Authentication: map[string]v1beta3.AuthenticationSpec{
				"apikey": {
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						ApiKey: &v1beta3.ApiKeyAuthenticationSpec{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "test"},
							},
						},
					},
					Credentials: v1beta3.Credentials{
						AuthorizationHeader: &v1beta3.Prefixed{Prefix: "APIKEY"},
					},
				},
			},
		},
	}

	runTests(t, "test-creds", baseAuthConfig, []validationTestCase{
		{
			desc: "valid - single credential source (authorizationHeader)",
		},
		{
			desc: "valid - single credential source (customHeader)",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authentication["apikey"] = v1beta3.AuthenticationSpec{
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						ApiKey: &v1beta3.ApiKeyAuthenticationSpec{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "test"},
							},
						},
					},
					Credentials: v1beta3.Credentials{
						CustomHeader: &v1beta3.CustomHeader{Named: v1beta3.Named{Name: "X-API-KEY"}},
					},
				}
			},
		},
		{
			desc: "valid - no credential source (defaults to Authorization: Bearer)",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authentication["apikey"] = v1beta3.AuthenticationSpec{
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						ApiKey: &v1beta3.ApiKeyAuthenticationSpec{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "test"},
							},
						},
					},
					Credentials: v1beta3.Credentials{},
				}
			},
		},
		{
			desc: "invalid - two credential sources (authorizationHeader + customHeader)",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authentication["apikey"] = v1beta3.AuthenticationSpec{
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						ApiKey: &v1beta3.ApiKeyAuthenticationSpec{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "test"},
							},
						},
					},
					Credentials: v1beta3.Credentials{
						AuthorizationHeader: &v1beta3.Prefixed{Prefix: "APIKEY"},
						CustomHeader:        &v1beta3.CustomHeader{Named: v1beta3.Named{Name: "X-API-KEY"}},
					},
				}
			},
			wantErrors: []string{"must have at most 1 items"},
		},
	})
}

// TestPlainIdentitySpecCELValidation tests the CEL validation rule on PlainIdentitySpec:
//
//	has(self.selector) != has(self.expression) -> "Use exactly one of: selector, expression"
func TestPlainIdentitySpecCELValidation(t *testing.T) {
	baseAuthConfig := v1beta3.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1beta3.AuthConfigSpec{
			Hosts: []string{"test-plain.example.com"},
			Authentication: map[string]v1beta3.AuthenticationSpec{
				"plain": {
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						Plain: &v1beta3.PlainIdentitySpec{
							Selector: "request.headers.x-user",
						},
					},
				},
			},
		},
	}

	runTests(t, "test-plain", baseAuthConfig, []validationTestCase{
		{
			desc: "valid - selector only",
		},
		{
			desc: "valid - expression only",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authentication["plain"] = v1beta3.AuthenticationSpec{
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						Plain: &v1beta3.PlainIdentitySpec{
							Expression: "request.headers['x-user']",
						},
					},
				}
			},
		},
		{
			desc: "invalid - neither selector nor expression",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authentication["plain"] = v1beta3.AuthenticationSpec{
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						Plain: &v1beta3.PlainIdentitySpec{},
					},
				}
			},
			wantErrors: []string{"Use exactly one of: selector, expression"},
		},
		{
			desc: "invalid - both selector and expression",
			mutate: func(ac *v1beta3.AuthConfig) {
				ac.Spec.Authentication["plain"] = v1beta3.AuthenticationSpec{
					AuthenticationMethodSpec: v1beta3.AuthenticationMethodSpec{
						Plain: &v1beta3.PlainIdentitySpec{
							Selector:   "request.headers.x-user",
							Expression: "request.headers['x-user']",
						},
					},
				}
			},
			wantErrors: []string{"Use exactly one of: selector, expression"},
		},
	})
}
