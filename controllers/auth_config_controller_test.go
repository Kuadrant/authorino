package controllers

import (
	"context"
	"fmt"
	"os"
	"testing"

	api "github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/httptest"
	"github.com/kuadrant/authorino/pkg/index"
	mock_index "github.com/kuadrant/authorino/pkg/index/mocks"
	"github.com/kuadrant/authorino/pkg/log"

	"github.com/golang/mock/gomock"
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
	return api.AuthConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthConfig",
			APIVersion: "authorino.kuadrant.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-config-1",
			Namespace: "authorino",
			Labels:    authConfigLabels,
		},
		Spec: api.AuthConfigSpec{
			Hosts: []string{"echo-api"},
			Identity: []*api.Identity{
				{
					Name: "keycloak",
					Oidc: &api.Identity_OidcConfig{
						Endpoint: "http://127.0.0.1:9001/auth/realms/demo",
					},
				},
			},
			Metadata: []*api.Metadata{
				{
					Name: "userinfo",
					UserInfo: &api.Metadata_UserInfo{
						IdentitySource: "keycloak",
					},
				},
				{
					Name: "resource-data",
					UMA: &api.Metadata_UMA{
						Endpoint: "http://127.0.0.1:9001/auth/realms/demo",
						Credentials: &v1.LocalObjectReference{
							Name: "secret",
						},
					},
				},
			},
			Authorization: []*api.Authorization{
				{
					Name: "main-policy",
					OPA: &api.Authorization_OPA{
						InlineRego: `
			method = object.get(input.context.request.http, "method", "")
			path = object.get(input.context.request.http, "path", "")

			allow {
              method == "GET"
              path = "/allow"
          }`,
					},
				},
				{
					Name: "some-extra-rules",
					JSON: &api.Authorization_JSONPatternMatching{
						Rules: []api.JSONPattern{
							{
								JSONPatternExpression: api.JSONPatternExpression{
									Selector: "context.identity.role",
									Operator: "eq",
									Value:    "admin",
								},
							},
						},
					},
				},
			},
		},
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
	return fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(initObjs...).Build()
}

func newTestAuthConfigReconciler(client client.WithWatch, i index.Index) *AuthConfigReconciler {
	return &AuthConfigReconciler{
		Client:            client,
		Logger:            log.WithName("test").WithName("authconfigreconciler"),
		Scheme:            nil,
		Index:             i,
		StatusReport:      NewStatusReportMap(),
		PreventCollisions: true,
	}
}

func TestReconcileAuthConfigOk(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, index.NewIndex())

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
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

	// Let's try to reconcile a non existing object.
	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "nonExistant", Namespace: authConfig.Namespace}})

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

func TestPreventHostCollisionEnabled(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{})
	authConfig.Spec.Hosts = append(authConfig.Spec.Hosts, "other.io", "yet-another.io")
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)

	indexMock.EXPECT().Empty().Return(false)
	indexMock.EXPECT().FindKeys(authConfigName.String()).Return([]string{}).AnyTimes()
	indexMock.EXPECT().FindId("echo-api").Return("other-namespace/other-auth-config-with-same-host", true)
	indexMock.EXPECT().FindId("other.io").Return("", false)
	indexMock.EXPECT().FindId("yet-another.io").Return(fmt.Sprintf("%s/other-auth-config-same-ns", authConfig.Namespace), true)
	indexMock.EXPECT().Set(authConfigName.String(), "other.io", gomock.Any(), true)

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

	assert.DeepEqual(t, result, ctrl.Result{})
	assert.NilError(t, err)
}

func TestPreventHostCollisionDisabled(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{})
	authConfig.Spec.Hosts = append(authConfig.Spec.Hosts, "other.io")
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)
	reconciler.PreventCollisions = false

	indexMock.EXPECT().Empty().Return(false)
	indexMock.EXPECT().FindKeys(authConfigName.String()).Return([]string{}).AnyTimes()
	indexMock.EXPECT().Set(authConfigName.String(), "echo-api", gomock.Any(), true)
	indexMock.EXPECT().Set(authConfigName.String(), "other.io", gomock.Any(), true)

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: authConfigName})

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

func TestEmptyIndex(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)

	authConfig := newTestAuthConfig(map[string]string{})
	authConfig.Status.Summary = api.Summary{
		Ready:                    true,
		HostsReady:               authConfig.Spec.Hosts,
		NumHostsReady:            fmt.Sprintf("%d/%d", len(authConfig.Spec.Hosts), len(authConfig.Spec.Hosts)),
		NumIdentitySources:       int64(len(authConfig.Spec.Identity)),
		NumMetadataSources:       int64(len(authConfig.Spec.Metadata)),
		NumAuthorizationPolicies: int64(len(authConfig.Spec.Authorization)),
		NumResponseItems:         int64(len(authConfig.Spec.Response)),
		FestivalWristbandEnabled: false,
	}
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	resourceId := authConfigName.String()
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, indexMock)

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
