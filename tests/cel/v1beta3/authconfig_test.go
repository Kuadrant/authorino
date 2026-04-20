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
	"k8s.io/apimachinery/pkg/runtime"
)

// TestKubernetesSubjectAccessReviewCELValidation tests the CEL validation rule
// that requires at least one of user, groups, or authorizationGroups to be specified
// in the kubernetesSubjectAccessReview authorization configuration.
//
// The validation rule is:
//
//	has(self.user) || size(self.groups) > 0 || has(self.authorizationGroups)
func TestKubernetesSubjectAccessReviewCELValidation(t *testing.T) {
	ctx := context.Background()

	// Base valid AuthConfig with kubernetesSubjectAccessReview authorization
	baseAuthConfig := v1beta3.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sar-authconfig",
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

	testCases := []struct {
		desc       string
		mutate     func(ac *v1beta3.AuthConfig)
		wantErrors []string
	}{
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
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ac := baseAuthConfig.DeepCopy()
			// Unique name for each test case to avoid conflicts
			ac.Name = fmt.Sprintf("test-sar-%v", time.Now().UnixNano())

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
