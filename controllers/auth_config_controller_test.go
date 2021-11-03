package controllers

import (
	"context"
	"os"
	"testing"

	"github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/pkg/cache"
	mock_cache "github.com/kuadrant/authorino/pkg/cache/mocks"
	"github.com/kuadrant/authorino/pkg/common/log"
	mocks "github.com/kuadrant/authorino/pkg/common/mocks"

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
	authServer := mocks.NewHttpServerMock("127.0.0.1:9001", map[string]mocks.HttpServerMockResponses{
		"/auth/realms/demo/.well-known/openid-configuration": {Status: 200, Body: `{ "issuer": "http://127.0.0.1:9001/auth/realms/demo" }`},
		"/auth/realms/demo/.well-known/uma2-configuration":   {Status: 200, Body: `{ "issuer": "http://127.0.0.1:9001/auth/realms/demo" }`},
	})
	defer authServer.Close()
	os.Exit(m.Run())
}

func newTestAuthConfig(authConfigLabels map[string]string) v1beta1.AuthConfig {
	return v1beta1.AuthConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthConfig",
			APIVersion: "authorino.3scale.net/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-config-1",
			Namespace: "authorino",
			Labels:    authConfigLabels,
		},
		Spec: v1beta1.AuthConfigSpec{
			Hosts: []string{"echo-api"},
			Identity: []*v1beta1.Identity{
				{
					Name: "keycloak",
					Oidc: &v1beta1.Identity_OidcConfig{
						Endpoint: "http://127.0.0.1:9001/auth/realms/demo",
					},
				},
			},
			Metadata: []*v1beta1.Metadata{
				{
					Name: "userinfo",
					UserInfo: &v1beta1.Metadata_UserInfo{
						IdentitySource: "keycloak",
					},
				},
				{
					Name: "resource-data",
					UMA: &v1beta1.Metadata_UMA{
						Endpoint: "http://127.0.0.1:9001/auth/realms/demo",
						Credentials: &v1.LocalObjectReference{
							Name: "secret",
						},
					},
				},
			},
			Authorization: []*v1beta1.Authorization{
				{
					Name: "main-policy",
					OPA: &v1beta1.Authorization_OPA{
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
					JSON: &v1beta1.Authorization_JSONPatternMatching{
						Rules: []v1beta1.Authorization_JSONPatternMatching_Rule{
							{
								Selector: "context.identity.role",
								Operator: "eq",
								Value:    "admin",
							},
							{
								Selector: "attributes.source.address.Address.SocketAddress.address",
								Operator: "eq",
								Value:    "80.133.21.75",
							},
						},
					}},
			},
		},
		Status: v1beta1.AuthConfigStatus{
			Ready: false,
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
	_ = v1beta1.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(initObjs...).Build()
}

func newTestAuthConfigReconciler(client client.WithWatch, c cache.Cache) *AuthConfigReconciler {
	return &AuthConfigReconciler{
		Client: client,
		Logger: log.WithName("test").WithName("authconfigreconciler"),
		Scheme: nil,
		Cache:  c,
	}
}

func TestReconcileAuthConfigOk(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, cache.NewCache())

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestMissingRequiredSecret(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{})
	client := newTestK8sClient(&authConfig)
	reconciler := newTestAuthConfigReconciler(client, cache.NewCache())

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.Check(t, errors.IsNotFound(err))    // Error should be "secret" not found.
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestAuthConfigNotFound(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, cache.NewCache())

	// Let's try to reconcile a non existing object.
	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "nonExistant", Namespace: authConfig.Namespace}})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestTranslateAuthConfig(t *testing.T) {
	// TODO
}

func TestHostColllision(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	cacheMock := mock_cache.NewMockCache(mockController)

	authConfig := newTestAuthConfig(map[string]string{})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, cacheMock)

	cacheMock.EXPECT().FindId("echo-api").Return("other-namespace/other-auth-config-with-same-host", true)

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.DeepEqual(t, result, ctrl.Result{})
	assert.NilError(t, err)
}

func TestMissingWatchedAuthConfigLabels(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	cacheMock := mock_cache.NewMockCache(mockController)

	authConfig := newTestAuthConfig(map[string]string{"authorino.3scale.net/managed-by": "authorino"})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, cacheMock)

	cacheMock.EXPECT().FindId("echo-api").Return("", false)
	cacheMock.EXPECT().Set("authorino/auth-config-1", "echo-api", gomock.Any(), true)

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestMatchingAuthConfigLabels(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	cacheMock := mock_cache.NewMockCache(mockController)

	authConfig := newTestAuthConfig(map[string]string{"authorino.3scale.net/managed-by": "authorino"})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, cacheMock)
	reconciler.LabelSelector = ToLabelSelector("authorino.3scale.net/managed-by=authorino")

	cacheMock.EXPECT().FindId("echo-api").Return("", false)
	cacheMock.EXPECT().Set("authorino/auth-config-1", "echo-api", gomock.Any(), true)

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}

func TestUnmatchingAuthConfigLabels(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	cacheMock := mock_cache.NewMockCache(mockController)

	authConfig := newTestAuthConfig(map[string]string{"authorino.3scale.net/managed-by": "other"})
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, cacheMock)
	reconciler.LabelSelector = ToLabelSelector("authorino.3scale.net/managed-by=authorino")

	cacheMock.EXPECT().Delete("authorino/auth-config-1")

	result, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})

	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{}) // Result should be empty
}
