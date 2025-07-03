package controllers

import (
	"context"
	"fmt"
	"os"
	"testing"

	api "github.com/kuadrant/authorino/api/v1beta3"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/httptest"
	"github.com/kuadrant/authorino/pkg/index"
	mock_index "github.com/kuadrant/authorino/pkg/index/mocks"
	"github.com/kuadrant/authorino/pkg/log"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestMain(m *testing.M) {
	authServer := httptest.NewHttpServerMock("127.0.0.1:9001", map[string]httptest.HttpServerMockResponseFunc{
		"/auth/realms/demo/.well-known/openid-configuration": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: `{ "issuer": "http://127.0.0.1:9001/auth/realms/demo" }`}
		},
		"/auth/realms/demo/.well-known/uma2-configuration": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: `{ "issuer": "http://127.0.0.1:9001/auth/realms/demo" }`}
		},
	})
	defer authServer.Close()
	os.Exit(m.Run())
}

func newTestAuthConfig(authConfigLabels map[string]string) api.AuthConfig {
	spec := api.AuthConfigSpec{
		Hosts: []string{"echo-api"},
		Authentication: map[string]api.AuthenticationSpec{
			"keycloak": {
				AuthenticationMethodSpec: api.AuthenticationMethodSpec{
					Jwt: &api.JwtAuthenticationSpec{
						IssuerUrl: "http://127.0.0.1:9001/auth/realms/demo",
					},
				},
				Defaults: map[string]api.ValueOrSelector{
					"source": {
						Value: runtime.RawExtension{Raw: []byte(`"test"`)},
					},
				},
			},
		},
		Metadata: map[string]api.MetadataSpec{
			"userinfo": {
				MetadataMethodSpec: api.MetadataMethodSpec{
					UserInfo: &api.UserInfoMetadataSpec{
						IdentitySource: "keycloak",
					},
				},
			},
			"resource-data": {
				MetadataMethodSpec: api.MetadataMethodSpec{
					Uma: &api.UmaMetadataSpec{
						Endpoint: "http://127.0.0.1:9001/auth/realms/demo",
						Credentials: &v1.LocalObjectReference{
							Name: "secret",
						},
					},
				},
			},
		},
		Authorization: map[string]api.AuthorizationSpec{
			"main-policy": {
				AuthorizationMethodSpec: api.AuthorizationMethodSpec{
					Opa: &api.OpaAuthorizationSpec{
						Rego: `
			method = object.get(input.context.request.http, "method", "")
			path = object.get(input.context.request.http, "path", "")

			allow if {
              method == "GET"
              path = "/allow"
          }`,
					},
				},
			},
			"some-extra-rules": {
				AuthorizationMethodSpec: api.AuthorizationMethodSpec{
					PatternMatching: &api.PatternMatchingAuthorizationSpec{
						Patterns: []api.PatternExpressionOrRef{
							{
								CelPredicate: api.CelPredicate{
									Predicate: "auth.identity.role == 'admin'",
								},
							},
						},
					},
				},
			},
		},
	}
	return api.AuthConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthConfig",
			APIVersion: "authorino.kuadrant.io/v1beta3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-config-1",
			Namespace: "authorino",
			Labels:    authConfigLabels,
		},
		Spec: spec,
	}
}

func newTestOAuthClientSecret() v1.Secret {
	return v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: "authorino",
		},
		Data: map[string][]byte{
			"clientID":     []byte("clientID"),
			"clientSecret": []byte("clientSecret"),
		},
	}
}

func newTestK8sClient(initObjs ...runtime.Object) client.WithWatch {
	scheme := runtime.NewScheme()
	_ = api.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(initObjs...).WithStatusSubresource(&api.AuthConfig{}).Build()
}

func newTestAuthConfigReconciler(client client.WithWatch, i index.Index) *AuthConfigReconciler {
	return &AuthConfigReconciler{
		Client:       client,
		Logger:       log.WithName("test").WithName("authconfigreconciler"),
		Scheme:       nil,
		Index:        i,
		StatusReport: NewStatusReportMap(),
	}
}

func TestReconcileAuthConfigOk(t *testing.T) {
	authConfigIndex := index.NewIndex()
	authConfig := newTestAuthConfig(map[string]string{})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, authConfigIndex)

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty

	config := authConfigIndex.Get("echo-api")
	assert.Check(t, config != nil)
	idConfig, _ := config.IdentityConfigs[0].(*evaluators.IdentityConfig)
	assert.Equal(t, idConfig.ExtendedProperties[0].Name, "source")
	// TODO(@guicassolato): assert other fields of the AuthConfig
}

func TestMissingRequiredSecret(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{})
	client := newTestK8sClient(&authConfig)
	reconciler := newTestAuthConfigReconciler(client, index.NewIndex())

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.Check(t, errors.IsNotFound(err))    // Error should be "secret" not found.
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestAuthConfigNotFound(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, index.NewIndex())

	// Let's try to reconcile a non-existing object.
	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "nonExistent", Namespace: authConfig.Namespace}})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestRemoveHostFromAuthConfig(t *testing.T) {
	authConfigIndex := index.NewIndex()
	authConfig := newTestAuthConfig(map[string]string{})
	authConfig.Spec.Hosts = append(authConfig.Spec.Hosts, "other.io")
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, authConfigIndex)

	_, _ = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	var config *evaluators.AuthConfig

	config = authConfigIndex.Get("echo-api")
	assert.Check(t, config != nil)

	config = authConfigIndex.Get("other.io")
	assert.Check(t, config != nil)

	authConfig.Spec.Hosts = []string{"echo-api"} // remove other.io
	_ = client.Update(context.Background(), &authConfig)

	_, _ = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	config = authConfigIndex.Get("echo-api")
	assert.Check(t, config != nil)

	config = authConfigIndex.Get("other.io")
	assert.Check(t, config == nil)
}

func TestTranslateAuthConfig(t *testing.T) {
	// TODO
}

func TestPreventHostCollisionExactMatches(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{})
	authConfig.Spec.Hosts = append(authConfig.Spec.Hosts, "other.io", "yet-another.io")
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)

	indexMock.EXPECT().Empty().Return(false)                                                                              // simulate index not empty, so it skips bootstraping
	indexMock.EXPECT().FindKeys(authConfigName.String()).Return([]string{}).AnyTimes()                                    // simulate no prexisting hosts linked to the authconfig to be reconciled
	indexMock.EXPECT().FindId("echo-api").Return("other-namespace/other-auth-config-with-same-host", true)                // simulate other existing authconfig with conflicting host, in a different namespace
	indexMock.EXPECT().FindId("other.io").Return(fmt.Sprintf("%s/other-auth-config-same-ns", authConfig.Namespace), true) // simulate other existing authconfig with conflicting host, in the same namespace
	indexMock.EXPECT().FindId("yet-another.io").Return("", false)                                                         // simulate no other existing authconfig with conflicting host

	indexMock.EXPECT().Set(authConfigName.String(), "yet-another.io", gomock.Any(), true) // expect only the new host to be indexed

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.DeepEqual(t, result, ctrl.Result{})
	assert.NilError(t, err)
}

func TestPreventHostCollisionAllowSupersedingHostSubsets(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{})
	authConfig.Spec.Hosts = []string{"echo-api.io"}
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}

	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)

	indexMock.EXPECT().Empty().Return(false).AnyTimes()                                // simulate index not empty, so it skips bootstraping
	indexMock.EXPECT().FindKeys(authConfigName.String()).Return([]string{}).AnyTimes() // simulate no prexisting hosts linked to the authconfig to be reconciled

	// allow superseding host subsets = false
	indexMock.EXPECT().FindId("echo-api.io").Return("other/other", true) // simulate other existing authconfig with conflicting host

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.DeepEqual(t, result, ctrl.Result{})
	assert.NilError(t, err)

	// allow superseding host subsets = true, conflicting host found and the new one is NOT a strict subset of the one found
	reconciler.AllowSupersedingHostSubsets = true
	indexMock.EXPECT().FindId("echo-api.io").Return("other/other-1", true)       // simulate other existing authconfig with conflicting host
	indexMock.EXPECT().FindKeys("other/other-1").Return([]string{"echo-api.io"}) // simulate identical host found linked to other authconfig (i.e. not a strict subset)

	result, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.DeepEqual(t, result, ctrl.Result{})
	assert.NilError(t, err)

	// allow superseding host subsets = true, conflicting host found but the new one is a strict subset of the one found
	reconciler.AllowSupersedingHostSubsets = true
	indexMock.EXPECT().FindId("echo-api.io").Return("other/other-2", true) // simulate other existing authconfig with conflicting host
	indexMock.EXPECT().FindKeys("other/other-2").Return([]string{"*.io"})  // simulate superset host found linked to other authconfig

	indexMock.EXPECT().Set(authConfigName.String(), "echo-api.io", gomock.Any(), true) // expect only the new host to be indexed

	result, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.DeepEqual(t, result, ctrl.Result{})
	assert.NilError(t, err)
}

func TestMissingWatchedAuthConfigLabels(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{"authorino.kuadrant.io/managed-by": "authorino"})
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)

	indexMock.EXPECT().Empty().Return(false)
	indexMock.EXPECT().FindKeys(authConfigName.String()).Return([]string{}).AnyTimes()
	indexMock.EXPECT().FindId("echo-api").Return("", false)
	indexMock.EXPECT().Set("authorino/auth-config-1", "echo-api", gomock.Any(), true)

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestMatchingAuthConfigLabels(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{"authorino.kuadrant.io/managed-by": "authorino"})
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)
	reconciler.LabelSelector = ToLabelSelector("authorino.kuadrant.io/managed-by=authorino")

	indexMock.EXPECT().Empty().Return(false)
	indexMock.EXPECT().FindKeys(authConfigName.String()).Return([]string{}).AnyTimes()
	indexMock.EXPECT().FindId("echo-api").Return("", false)
	indexMock.EXPECT().Set("authorino/auth-config-1", "echo-api", gomock.Any(), true)

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestUnmatchingAuthConfigLabels(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{"authorino.kuadrant.io/managed-by": "other"})
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)
	reconciler.LabelSelector = ToLabelSelector("authorino.kuadrant.io/managed-by=authorino")

	indexMock.EXPECT().Empty().Return(false)
	indexMock.EXPECT().FindKeys(authConfigName.String()).Return([]string{}).AnyTimes()
	indexMock.EXPECT().Delete(authConfigName.String())

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestEmptyAuthConfigIdentitiesDefaultsToAnonymousAccess(t *testing.T) {
	r := &AuthConfigReconciler{}
	config, err := r.translateAuthConfig(context.TODO(), &api.AuthConfig{
		Spec: api.AuthConfigSpec{
			Hosts: []string{"app.com"},
		},
	})
	assert.NilError(t, err)
	assert.Equal(t, len(config.IdentityConfigs), 1)
}

func TestBootstrapIndex(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{"scope": "in"})
	expectedNumResponseItems := 0
	if authConfig.Spec.Response != nil {
		expectedNumResponseItems = len(authConfig.Spec.Response.Success.DynamicMetadata) + len(authConfig.Spec.Response.Success.Headers)
	}
	authConfig.Status.Summary = api.AuthConfigStatusSummary{
		Ready:                    true,
		HostsReady:               authConfig.Spec.Hosts,
		NumHostsReady:            fmt.Sprintf("%d/%d", len(authConfig.Spec.Hosts), len(authConfig.Spec.Hosts)),
		NumIdentitySources:       int64(len(authConfig.Spec.Authentication)),
		NumMetadataSources:       int64(len(authConfig.Spec.Metadata)),
		NumAuthorizationPolicies: int64(len(authConfig.Spec.Authorization)),
		NumResponseItems:         int64(expectedNumResponseItems),
		FestivalWristbandEnabled: false,
	}

	authConfigOutOfScope := newTestAuthConfig(map[string]string{"scope": "out"})
	authConfigOutOfScope.Status.Summary = api.AuthConfigStatusSummary{
		Ready:                    true,
		HostsReady:               authConfig.Spec.Hosts,
		NumHostsReady:            fmt.Sprintf("%d/%d", len(authConfig.Spec.Hosts), len(authConfig.Spec.Hosts)),
		NumIdentitySources:       int64(len(authConfig.Spec.Authentication)),
		NumMetadataSources:       int64(len(authConfig.Spec.Metadata)),
		NumAuthorizationPolicies: int64(len(authConfig.Spec.Authorization)),
		NumResponseItems:         int64(expectedNumResponseItems),
		FestivalWristbandEnabled: false,
	}

	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	resourceId := authConfigName.String()
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)
	reconciler.LabelSelector = ToLabelSelector("scope=in")

	indexMock.EXPECT().Empty().Return(true)
	indexMock.EXPECT().FindKeys(resourceId).Return([]string{}).AnyTimes()
	indexMock.EXPECT().FindId("echo-api").Times(2).Return("", false).Return(resourceId, true)
	indexMock.EXPECT().Set("authorino/auth-config-1", "echo-api", gomock.Any(), true).Times(2)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.NilError(t, err)
}

func BenchmarkReconcileAuthConfig(b *testing.B) {
	authConfig := newTestAuthConfig(map[string]string{})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, index.NewIndex())

	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})
	}
	b.StopTimer()
	assert.NilError(b, err)
}
