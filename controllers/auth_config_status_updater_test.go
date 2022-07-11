package controllers

import (
	"context"
	"testing"

	api "github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/pkg/cache"
	mock_cache "github.com/kuadrant/authorino/pkg/cache/mocks"
	"github.com/kuadrant/authorino/pkg/log"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestAuthConfigStatusUpdater_Reconcile(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	cache := mock_cache.NewMockCache(mockctrl)
	authConfig := mockStatusUpdateAuthConfig()
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client, cache)

	cache.EXPECT().FindKeys("authorino/auth-config-1").Return([]string{"echo-api"})
	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_MissingWatchedAuthConfigLabels(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	cache := mock_cache.NewMockCache(mockctrl)
	authConfig := mockStatusUpdateAuthConfigWithLabels(map[string]string{})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client, cache)

	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_MatchingAuthConfigLabels(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	cache := mock_cache.NewMockCache(mockctrl)
	authConfig := mockStatusUpdateAuthConfigWithLabels(map[string]string{"authorino.kuadrant.io/managed-by": "authorino", "other-label": "other value"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client, cache)

	cache.EXPECT().FindKeys("authorino/auth-config-1").Return([]string{"echo-api"})
	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_UnmatchingAuthConfigLabels(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	cache := mock_cache.NewMockCache(mockctrl)
	authConfig := newTestAuthConfig(map[string]string{"authorino.kuadrant.io/managed-by": "other"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client, cache)

	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_NotReady(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	cache := mock_cache.NewMockCache(mockctrl)
	authConfig := mockStatusUpdateAuthConfig()
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client, cache)

	var result reconcile.Result
	var err error
	var authConfigCheck api.AuthConfig

	cache.EXPECT().FindKeys("authorino/auth-config-1").Return([]string{}).Times(2)

	// try to reconcile once
	result, err = reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Check(t, result.Requeue)
	assert.NilError(t, err)

	authConfigCheck = api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready())

	// try to reconcile again with no change in the status
	result, err = reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Check(t, result.Requeue)
	assert.NilError(t, err)

	authConfigCheck = api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_HostNotLinked(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	cache := mock_cache.NewMockCache(mockctrl)
	authConfig := mockStatusUpdateAuthConfigWithHosts([]string{"my-api.com", "my-api.local"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client, cache)

	cache.EXPECT().FindKeys("authorino/auth-config-1").Return([]string{"my-api.com"})
	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Check(t, result.Requeue)
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	status := authConfigCheck.Status
	assert.Check(t, !status.Ready())
	assert.Equal(t, status.Conditions[0].Reason, api.StatusReasonHostNotLinked)
	assert.Equal(t, status.Conditions[0].Message, "One or more hosts not linked to the resource")
	assert.Equal(t, len(status.Summary.HostsReady), 1)
	assert.Equal(t, status.Summary.HostsReady[0], "my-api.com")
}

func mockStatusUpdateAuthConfig() api.AuthConfig {
	return mockStatusUpdateAuthConfigWithLabelsAndHosts(map[string]string{"authorino.kuadrant.io/managed-by": "authorino"}, []string{"echo-api"})
}

func mockStatusUpdateAuthConfigWithHosts(hosts []string) api.AuthConfig {
	return mockStatusUpdateAuthConfigWithLabelsAndHosts(map[string]string{"authorino.kuadrant.io/managed-by": "authorino"}, hosts)
}

func mockStatusUpdateAuthConfigWithLabels(authConfigLabels map[string]string) api.AuthConfig {
	return mockStatusUpdateAuthConfigWithLabelsAndHosts(authConfigLabels, []string{"echo-api"})
}

func mockStatusUpdateAuthConfigWithLabelsAndHosts(labels map[string]string, hosts []string) api.AuthConfig {
	return api.AuthConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthConfig",
			APIVersion: "authorino.kuadrant.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-config-1",
			Namespace: "authorino",
			Labels:    labels,
		},
		Spec: api.AuthConfigSpec{
			Hosts: hosts,
		},
	}
}

func mockStatusUpdaterReconciler(client client.WithWatch, c cache.Cache) *AuthConfigStatusUpdater {
	return &AuthConfigStatusUpdater{
		Client:        client,
		Logger:        log.WithName("test").WithName("authconfigstatusupdater"),
		Cache:         c,
		LabelSelector: ToLabelSelector("authorino.kuadrant.io/managed-by=authorino"),
	}
}
