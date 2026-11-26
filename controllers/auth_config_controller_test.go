package controllers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/go-logr/logr/funcr"
	api "github.com/kuadrant/authorino/api/v1beta3"
	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
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
						Version: "v1",
						Rego: `
			method := input.context.request.http.method
			path := input.context.request.http.path

			allow if {
              method == "GET"
              path == "/allow"
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

func TestReconcileDeindexesTerminatingAuthConfig(t *testing.T) {
	authConfigIndex := index.NewIndex()
	authConfig := newTestAuthConfig(map[string]string{})
	authConfig.Finalizers = []string{"example.com/hold"}
	authConfigName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}
	secret := newTestOAuthClientSecret()
	client := newTestK8sClient(&authConfig, &secret)
	reconciler := newTestAuthConfigReconciler(client, authConfigIndex)

	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: authConfigName})
	assert.NilError(t, err)
	assert.Check(t, authConfigIndex.Get("echo-api") != nil)

	// the finalizer holds the object, so this only sets the deletion timestamp
	assert.NilError(t, client.Delete(t.Context(), &authConfig))

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: authConfigName})
	assert.NilError(t, err)
	assert.DeepEqual(t, result, ctrl.Result{})
	assert.Check(t, authConfigIndex.Get("echo-api") == nil)
	_, reported := reconciler.StatusReport.Get(authConfigName.String())
	assert.Check(t, !reported)
}

// The Secret reconciler only updates AuthConfigs that are indexed, so a Secret created or deleted
// while an AuthConfig is translated reaches it only if it lists its Secrets again once indexed.
func TestReconcileListsAPIKeySecretsAgainOnceIndexed(t *testing.T) {
	authConfig := api.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "talker-api-protection", Namespace: "authorino"},
		Spec: api.AuthConfigSpec{
			Hosts: []string{"talker-api"},
			Authentication: map[string]api.AuthenticationSpec{
				"api-key": {
					AuthenticationMethodSpec: api.AuthenticationMethodSpec{
						ApiKey: &api.ApiKeyAuthenticationSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"group": "friends"}}},
					},
				},
			},
		},
	}
	apiKeySecret := func(name, key string) v1.Secret {
		return v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "authorino", Labels: map[string]string{"group": "friends"}},
			Data:       map[string][]byte{"api_key": []byte(key)},
		}
	}
	created := apiKeySecret("created", "created-during-translation")
	deleted := apiKeySecret("deleted", "deleted-during-translation")

	// the first list, made during translation, sees the Secrets as they were before
	firstSecretList := true
	authConfigIndex := index.NewIndex()
	scheme := runtime.NewScheme()
	_ = api.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&authConfig, &created).WithStatusSubresource(&api.AuthConfig{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if secrets, ok := list.(*v1.SecretList); ok && firstSecretList {
					firstSecretList = false
					secrets.Items = []v1.Secret{deleted}
					return nil
				}
				if _, ok := list.(*v1.SecretList); ok && authConfigIndex.Get("talker-api") == nil {
					t.Error("listed the Secrets again before the AuthConfig was indexed")
				}
				return c.List(ctx, list, opts...)
			},
		}).Build()
	reconciler := newTestAuthConfigReconciler(k8sClient, authConfigIndex)

	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}})
	assert.NilError(t, err)

	indexed := authConfigIndex.Get("talker-api")
	assert.Assert(t, indexed != nil)
	identity, ok := indexed.IdentityConfigs[0].(*evaluators.IdentityConfig)
	assert.Assert(t, ok)
	assert.Check(t, acceptsAPIKey(t, identity, "created-during-translation"), "expected the Secret created during translation to be loaded")
	assert.Check(t, !acceptsAPIKey(t, identity, "deleted-during-translation"), "expected the Secret deleted during translation to be dropped")
}

func TestReconcileFailsWhenListingIdentitySecretsAgainFails(t *testing.T) {
	authConfig := api.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "talker-api-protection", Namespace: "authorino"},
		Spec: api.AuthConfigSpec{
			Hosts: []string{"talker-api"},
			Authentication: map[string]api.AuthenticationSpec{
				"api-key": {
					AuthenticationMethodSpec: api.AuthenticationMethodSpec{
						ApiKey: &api.ApiKeyAuthenticationSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"group": "friends"}}},
					},
				},
			},
		},
	}
	secretLists := 0
	scheme := runtime.NewScheme()
	_ = api.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&authConfig).WithStatusSubresource(&api.AuthConfig{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*v1.SecretList); ok {
					if secretLists++; secretLists > 1 {
						return fmt.Errorf("cache not synced")
					}
				}
				return c.List(ctx, list, opts...)
			},
		}).Build()
	reconciler := newTestAuthConfigReconciler(k8sClient, index.NewIndex())
	resourceName := types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}

	// returning the error requeues the AuthConfig, so the Secrets are listed again
	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: resourceName})
	assert.ErrorContains(t, err, "cache not synced")

	// the hosts are indexed and served by now, so the report lists them with the error
	report, _ := reconciler.StatusReport.Get(resourceName.String())
	assert.Equal(t, report.Reason, api.StatusReasonCachingError)
	assert.Check(t, strings.Contains(report.Message, "cache not synced"))
	assert.DeepEqual(t, report.LinkedHosts, []string{"talker-api"})
}

func acceptsAPIKey(t *testing.T, identity *evaluators.IdentityConfig, key string) bool {
	t.Helper()
	pipeline := mock_auth.NewMockAuthPipeline(gomock.NewController(t))
	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{Headers: map[string]string{"authorization": "Bearer " + key}}).AnyTimes()
	_, err := identity.APIKey.Call(pipeline, t.Context())
	return err == nil
}

type cleanRecordingEvaluator struct{ cleaned bool }

func (e *cleanRecordingEvaluator) Call(auth.AuthPipeline, context.Context) (interface{}, error) {
	return nil, nil
}

func (e *cleanRecordingEvaluator) Clean(context.Context) error {
	e.cleaned = true
	return nil
}

func TestCleanConfigsCleansTheConfigItServes(t *testing.T) {
	authConfigIndex := index.NewIndex()
	own := &cleanRecordingEvaluator{}
	assert.NilError(t, authConfigIndex.Set("authorino/a", "api.example.com", evaluators.AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{own}}, true))
	reconciler := newTestAuthConfigReconciler(newTestK8sClient(), authConfigIndex)

	assert.NilError(t, reconciler.cleanConfigs(t.Context(), "authorino/a"))
	assert.Check(t, own.cleaned)
}

// A deletion request de-indexes an AuthConfig held by a finalizer, and its host can go to another
// AuthConfig before it is gone. The index still lists the released host for it, so the reconcile
// after the finalizer is removed must not clean whoever serves that host now.
func TestCleanConfigsSkipsHostsServedByAnotherAuthConfig(t *testing.T) {
	testCases := map[string]struct{ otherId, otherHost string }{
		"same host":     {otherId: "other/same-host", otherHost: "api.example.com"},
		"wildcard host": {otherId: "other/wildcard", otherHost: "*.example.com"},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			authConfigIndex := index.NewIndex()
			released := &cleanRecordingEvaluator{}
			assert.NilError(t, authConfigIndex.Set("authorino/released", "api.example.com", evaluators.AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{released}}, true))
			authConfigIndex.Delete("authorino/released")
			other := &cleanRecordingEvaluator{}
			assert.NilError(t, authConfigIndex.Set(tc.otherId, tc.otherHost, evaluators.AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{other}}, true))
			reconciler := newTestAuthConfigReconciler(newTestK8sClient(), authConfigIndex)

			assert.NilError(t, reconciler.cleanConfigs(t.Context(), "authorino/released"))
			assert.Check(t, !other.cleaned, "expected the evaluators of %s to be left running", tc.otherId)
		})
	}
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

func translateJwtAuthConfig(t *testing.T, jwt api.JwtAuthenticationSpec) []string {
	t.Helper()

	var logs []string
	recorder := funcr.New(func(prefix, args string) {
		logs = append(logs, args)
	}, funcr.Options{})

	r := &AuthConfigReconciler{}
	_, err := r.translateAuthConfig(log.IntoContext(context.TODO(), recorder), &api.AuthConfig{
		Spec: api.AuthConfigSpec{
			Hosts: []string{"app.com"},
			Authentication: map[string]api.AuthenticationSpec{
				"keycloak": {
					AuthenticationMethodSpec: api.AuthenticationMethodSpec{
						Jwt: &jwt,
					},
				},
			},
		},
	})
	assert.NilError(t, err)
	return logs
}

func logsContain(logs []string, substr string) bool {
	for _, l := range logs {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

const (
	jwtTestIssuerUrl            = "http://127.0.0.1:9001/auth/realms/demo"
	unsafeIssuerDefaultLogMsg   = "does not verify the token issuer (iss) claim"
	unsafeAudienceDefaultLogMsg = "does not verify the token audience (aud) claim"
)

func TestJwtIssuerUnsetLogsWarning(t *testing.T) {
	logs := translateJwtAuthConfig(t, api.JwtAuthenticationSpec{IssuerUrl: jwtTestIssuerUrl})
	assert.Check(t, logsContain(logs, unsafeIssuerDefaultLogMsg), "expected an INFO log warning about the unverified issuer default")
}

func TestJwtIssuerSetDoesNotLogWarning(t *testing.T) {
	logs := translateJwtAuthConfig(t, api.JwtAuthenticationSpec{IssuerUrl: jwtTestIssuerUrl, Issuer: jwtTestIssuerUrl})
	assert.Check(t, !logsContain(logs, unsafeIssuerDefaultLogMsg), "did not expect the issuer warning when issuer is set")
}

func TestJwtAudiencesUnsetLogsWarning(t *testing.T) {
	logs := translateJwtAuthConfig(t, api.JwtAuthenticationSpec{IssuerUrl: jwtTestIssuerUrl})
	assert.Check(t, logsContain(logs, unsafeAudienceDefaultLogMsg), "expected an INFO log warning about the unverified audience default")
}

func TestJwtAudiencesSetDoesNotLogWarning(t *testing.T) {
	logs := translateJwtAuthConfig(t, api.JwtAuthenticationSpec{IssuerUrl: jwtTestIssuerUrl, Audiences: []string{"my-api.io"}})
	assert.Check(t, !logsContain(logs, unsafeAudienceDefaultLogMsg), "did not expect the audience warning when audiences is set")
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

func TestBootstrapIndexSkipsTerminatingAuthConfigs(t *testing.T) {
	withHostsReady := func(name, host string) api.AuthConfig {
		authConfig := newTestAuthConfig(map[string]string{})
		authConfig.Name = name
		authConfig.Spec.Hosts = []string{host}
		authConfig.Status.Summary.HostsReady = []string{host}
		return authConfig
	}
	serving := withHostsReady("serving", "serving.io")
	// the status updater skips a terminating AuthConfig, so its last status still lists its hosts
	terminating := withHostsReady("terminating", "terminating.io")
	terminating.Finalizers = []string{"example.com/hold"}
	terminating.DeletionTimestamp = &metav1.Time{Time: time.Now()}

	authConfigIndex := index.NewIndex()
	reconciler := newTestAuthConfigReconciler(newTestK8sClient(&serving, &terminating), authConfigIndex)

	assert.NilError(t, reconciler.bootstrapIndex(t.Context()))
	assert.Check(t, authConfigIndex.Get("serving.io") != nil)
	assert.Check(t, authConfigIndex.Get("terminating.io") == nil)
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

func TestAuthConfigPredicate(t *testing.T) {
	stored := api.AuthConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "talker-api",
			Namespace:       "default",
			UID:             "uid-1",
			Generation:      1,
			ResourceVersion: "100",
			Labels:          map[string]string{"group": "a"},
			Annotations:     map[string]string{"note": "a"},
		},
		Status: api.AuthConfigStatus{Summary: api.AuthConfigStatusSummary{Ready: false}},
	}

	updated := func(from api.AuthConfig, change func(*api.AuthConfig)) *api.AuthConfig {
		authConfig := from.DeepCopy()
		authConfig.ResourceVersion = "101"
		change(authConfig)
		return authConfig
	}

	unwatched := *stored.DeepCopy()
	unwatched.Labels = map[string]string{"group": "z"}

	testCases := map[string]struct {
		old, new *api.AuthConfig
		want     bool
	}{
		"status only": {
			new:  updated(stored, func(a *api.AuthConfig) { a.Status.Summary.Ready = true }),
			want: false,
		},
		"finalizers only": {
			new:  updated(stored, func(a *api.AuthConfig) { a.Finalizers = []string{"example.com/hold"} }),
			want: false,
		},
		"spec": {
			new:  updated(stored, func(a *api.AuthConfig) { a.Generation = 2 }),
			want: true,
		},
		// the API server bumps the generation when it sets the deletion timestamp of an object held by a finalizer
		"deletion requested": {
			new: updated(stored, func(a *api.AuthConfig) {
				a.Finalizers = []string{"example.com/hold"}
				a.DeletionTimestamp = &metav1.Time{}
				a.Generation = 2
			}),
			want: true,
		},
		"already terminating, status only": {
			old: updated(stored, func(a *api.AuthConfig) {
				a.Finalizers = []string{"example.com/hold"}
				a.DeletionTimestamp = &metav1.Time{}
			}),
			new: updated(stored, func(a *api.AuthConfig) {
				a.ResourceVersion = "102"
				a.Finalizers = []string{"example.com/hold"}
				a.DeletionTimestamp = &metav1.Time{}
				a.Status.Summary.Ready = true
			}),
			want: false,
		},
		// client-go reports an AuthConfig deleted and recreated during a relist as an update.
		"replaced": {
			new: updated(stored, func(a *api.AuthConfig) {
				a.UID = "uid-2"
				a.Spec.Hosts = []string{"other.io"}
			}),
			want: true,
		},
		"labels, moved out of the selector": {
			new:  updated(stored, func(a *api.AuthConfig) { a.Labels["group"] = "b" }),
			want: true,
		},
		"annotations": {
			new:  updated(stored, func(a *api.AuthConfig) { a.Annotations["note"] = "b" }),
			want: true,
		},
		"periodic resync": {
			new:  stored.DeepCopy(),
			want: true,
		},
		"status only, not watched": {
			old:  unwatched.DeepCopy(),
			new:  updated(unwatched, func(a *api.AuthConfig) { a.Status.Summary.Ready = true }),
			want: false,
		},
		"spec, not watched": {
			old:  unwatched.DeepCopy(),
			new:  updated(unwatched, func(a *api.AuthConfig) { a.Generation = 2 }),
			want: false,
		},
	}

	filter := authConfigPredicate(ToLabelSelector("group=a"))
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			old := tc.old
			if old == nil {
				old = stored.DeepCopy()
			}
			assert.Equal(t, filter.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: tc.new}), tc.want)
		})
	}

	assert.Check(t, filter.Create(event.CreateEvent{Object: stored.DeepCopy()}))
	assert.Check(t, filter.Delete(event.DeleteEvent{Object: stored.DeepCopy()}))
	assert.Check(t, !filter.Create(event.CreateEvent{Object: unwatched.DeepCopy()}))
}
