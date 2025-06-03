package controllers

import (
	"context"
	"testing"

	api "github.com/kuadrant/authorino/api/v1beta3"
	"github.com/kuadrant/authorino/pkg/log"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
	k8score "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestAuthConfigStatusUpdater_Reconcile(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	authConfig := mockStatusUpdateAuthConfig()
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client)
	reconciler.StatusReport.Set(resourceName.String(), api.StatusReasonReconciled, "", []string{"echo-api"})

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_MissingWatchedAuthConfigLabels(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	authConfig := mockStatusUpdateAuthConfigWithLabels(map[string]string{})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client)

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_MatchingAuthConfigLabels(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	authConfig := mockStatusUpdateAuthConfigWithLabels(map[string]string{"authorino.kuadrant.io/managed-by": "authorino", "other-label": "other value"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client)
	reconciler.StatusReport.Set(resourceName.String(), api.StatusReasonReconciled, "", []string{"echo-api"})

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_UnmatchingAuthConfigLabels(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	authConfig := newTestAuthConfig(map[string]string{"authorino.kuadrant.io/managed-by": "other"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client)

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_NotReady(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	authConfig := mockStatusUpdateAuthConfig()
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client)

	var result reconcile.Result
	var err error
	var authConfigCheck api.AuthConfig

	// try to reconcile once
	result, err = reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: resourceName})

	assert.Check(t, result.Requeue)
	assert.NilError(t, err)

	authConfigCheck = api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready())

	// try to reconcile again with no change in the status
	result, err = reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: resourceName})

	assert.Check(t, result.Requeue)
	assert.NilError(t, err)

	authConfigCheck = api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready())
}

func TestAuthConfigStatusUpdater_HostNotLinked(t *testing.T) {
	mockctrl := gomock.NewController(t)
	defer mockctrl.Finish()

	authConfig := mockStatusUpdateAuthConfigWithHosts([]string{"my-api.com", "my-api.local"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := mockStatusUpdaterReconciler(client)
	reconciler.StatusReport.Set(resourceName.String(), api.StatusReasonHostsNotLinked, "one or more hosts are not linked to the resource", []string{"my-api.com"})

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: resourceName})

	assert.Check(t, result.Requeue)
	assert.NilError(t, err)

	authConfigCheck := api.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	status := authConfigCheck.Status
	assert.Equal(t, len(status.Conditions), 2)
	assert.Equal(t, status.Conditions[0].Type, api.StatusConditionAvailable)
	assert.Equal(t, status.Conditions[0].Status, k8score.ConditionTrue)
	assert.Equal(t, status.Conditions[0].Reason, api.StatusReasonHostsLinked)
	assert.Equal(t, status.Conditions[0].Message, "")
	assert.Equal(t, status.Conditions[1].Type, api.StatusConditionReady)
	assert.Equal(t, status.Conditions[1].Status, k8score.ConditionFalse)
	assert.Equal(t, status.Conditions[1].Reason, api.StatusReasonHostsNotLinked)
	assert.Equal(t, status.Conditions[1].Message, "One or more hosts are not linked to the resource")
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
			APIVersion: "authorino.kuadrant.io/v1beta3",
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

func mockStatusUpdaterReconciler(client client.WithWatch) *AuthConfigStatusUpdater {
	return &AuthConfigStatusUpdater{
		Client:        client,
		Logger:        log.WithName("test").WithName("authconfigstatusupdater"),
		StatusReport:  NewStatusReportMap(),
		LabelSelector: ToLabelSelector("authorino.kuadrant.io/managed-by=authorino"),
	}
}
