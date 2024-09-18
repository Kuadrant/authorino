package controllers

import (
	"context"
	"testing"

	"gotest.tools/assert"

	controller_builder "github.com/kuadrant/authorino/controllers/builder"
	mock_controller_builder "github.com/kuadrant/authorino/controllers/builder/mocks"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators"
	identity_evaluators "github.com/kuadrant/authorino/pkg/evaluators/identity"
	mock_index "github.com/kuadrant/authorino/pkg/index/mocks"
	"github.com/kuadrant/authorino/pkg/log"

	"github.com/golang/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type isPredicate struct {
}

func (c *isPredicate) Matches(x interface{}) bool {
	_, ok := x.(builder.Predicates)
	return ok // TODO: find a better way to check this
}

func (c *isPredicate) String() string {
	return "contains 1 predicate"
}

type fakeAPIKeyIdentityConfig struct {
	evaluator          *identity_evaluators.APIKey
	deleted, refreshed bool
}

func (i *fakeAPIKeyIdentityConfig) Call(_ auth.AuthPipeline, _ context.Context) (interface{}, error) {
	return nil, nil
}

func (i *fakeAPIKeyIdentityConfig) AddK8sSecretBasedIdentity(ctx context.Context, new v1.Secret) {
	i.evaluator.AddK8sSecretBasedIdentity(ctx, new)
	i.refreshed = true
}

func (i *fakeAPIKeyIdentityConfig) RevokeK8sSecretBasedIdentity(ctx context.Context, deleted types.NamespacedName) {
	i.evaluator.RevokeK8sSecretBasedIdentity(ctx, deleted)
	i.deleted = true
}

func (i *fakeAPIKeyIdentityConfig) GetK8sSecretLabelSelectors() labels.Selector {
	return i.evaluator.GetK8sSecretLabelSelectors()
}

type secretReconcilerTest struct {
	SecretReconciler *SecretReconciler
	Secret           v1.Secret
	AuthConfig       *evaluators.AuthConfig
}

func newSecretReconcilerTest(mockCtrl *gomock.Controller, secretLabels map[string]string) secretReconcilerTest {
	secret := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bill",
			Namespace: "authorino",
			Labels:    secretLabels,
		},
		Data: map[string][]byte{
			"api_key": []byte("123456"),
		},
	}

	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)

	// Create a fake k8s client with an existing secret.
	fakeK8sClient := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(&secret).Build()

	apiKeyLabelSelectors, _ := labels.Parse("target=echo-api")
	indexedAuthConfig := &evaluators.AuthConfig{
		Labels: map[string]string{"namespace": "authorino", "name": "api-protection"},
		IdentityConfigs: []auth.AuthConfigEvaluator{&fakeAPIKeyIdentityConfig{
			evaluator: identity_evaluators.NewApiKeyIdentity("api-key", apiKeyLabelSelectors, "", []string{}, auth.NewAuthCredential("", ""), fakeK8sClient, context.TODO()),
		}},
	}
	indexMock := mock_index.NewMockIndex(mockCtrl)
	indexMock.EXPECT().List().Return([]*evaluators.AuthConfig{indexedAuthConfig}).MaxTimes(1)

	secretReconciler := &SecretReconciler{
		Client:        fakeK8sClient,
		Logger:        log.WithName("test").WithName("secretreconciler"),
		Scheme:        nil,
		Index:         indexMock,
		LabelSelector: ToLabelSelector("authorino.kuadrant.io/managed-by=authorino"),
	}

	return secretReconcilerTest{
		secretReconciler,
		secret,
		indexedAuthConfig,
	}
}

func (t *secretReconcilerTest) reconcile() (reconcile.Result, error) {
	return t.SecretReconciler.Reconcile(context.Background(), controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: t.Secret.Namespace,
			Name:      t.Secret.Name,
		},
	})
}

func TestSetupSecretReconcilerWithManager(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	reconcilerTest := newSecretReconcilerTest(mockCtrl, map[string]string{})
	secretReconciler := reconcilerTest.SecretReconciler

	builder := mock_controller_builder.NewMockControllerBuilder(mockCtrl)

	newController = func(m manager.Manager) controller_builder.ControllerBuilder {
		return builder
	}

	builder.EXPECT().For(gomock.Any(), &isPredicate{}).Return(builder)
	builder.EXPECT().Complete(secretReconciler)

	_ = secretReconciler.SetupWithManager(nil)
}

func TestMissingWatchedSecretLabels(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	// secret missing the authorino "managed-by" label
	reconcilerTest := newSecretReconcilerTest(mockCtrl, map[string]string{
		"target": "echo-api",
	})

	_, err := reconcilerTest.reconcile()

	apiKeyIdentityConfig, _ := reconcilerTest.AuthConfig.IdentityConfigs[0].(*fakeAPIKeyIdentityConfig)

	assert.Check(t, apiKeyIdentityConfig.deleted)
	assert.Check(t, !apiKeyIdentityConfig.refreshed)
	assert.NilError(t, err)
}

func TestUnmatchingSecretLabels(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	// secret with the authorino "managed-by" label but not the same labels as specified in the auth config
	reconcilerTest := newSecretReconcilerTest(mockCtrl, map[string]string{
		"authorino.kuadrant.io/managed-by": "authorino",
	})

	_, err := reconcilerTest.reconcile()

	apiKeyIdentityConfig, _ := reconcilerTest.AuthConfig.IdentityConfigs[0].(*fakeAPIKeyIdentityConfig)

	assert.Check(t, apiKeyIdentityConfig.deleted)
	assert.Check(t, !apiKeyIdentityConfig.refreshed)
	assert.NilError(t, err)
}

func TestMatchingSecretLabels(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	// secret with the authorino "managed-by" label and the same labels as specified in the auth config
	reconcilerTest := newSecretReconcilerTest(mockCtrl, map[string]string{
		"authorino.kuadrant.io/managed-by": "authorino",
		"target":                           "echo-api",
	})

	_, err := reconcilerTest.reconcile()

	apiKeyIdentityConfig, _ := reconcilerTest.AuthConfig.IdentityConfigs[0].(*fakeAPIKeyIdentityConfig)

	assert.Check(t, !apiKeyIdentityConfig.deleted)
	assert.Check(t, apiKeyIdentityConfig.refreshed)
	assert.NilError(t, err)
}
