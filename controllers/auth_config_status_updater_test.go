package controllers

import (
	"context"
	"testing"

	"github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/pkg/common/log"

	"gotest.tools/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newStatusUpdateAuthConfig(authConfigLabels map[string]string) v1beta1.AuthConfig {
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
		},
		Status: v1beta1.AuthConfigStatus{
			Ready: false,
		},
	}
}

func newStatusUpdaterReconciler(client client.WithWatch) *AuthConfigStatusUpdater {
	return &AuthConfigStatusUpdater{
		Client: client,
		Logger: log.WithName("test").WithName("authconfigstatusupdater"),
	}
}

func TestAuthConfigStatusUpdater_Reconcile(t *testing.T) {
	authConfig := newStatusUpdateAuthConfig(map[string]string{})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := newStatusUpdaterReconciler(client)

	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := v1beta1.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, authConfigCheck.Status.Ready)
}

func TestAuthConfigStatusUpdater_MissingWatchedAuthConfigLabels(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{"authorino.3scale.net/managed-by": "authorino"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := newStatusUpdaterReconciler(client)

	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := v1beta1.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, authConfigCheck.Status.Ready)
}

func TestAuthConfigStatusUpdater_MatchingAuthConfigLabels(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{"authorino.3scale.net/managed-by": "authorino"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := newStatusUpdaterReconciler(client)
	reconciler.LabelSelector = ToLabelSelector("authorino.3scale.net/managed-by=authorino")

	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := v1beta1.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, authConfigCheck.Status.Ready)
}

func TestAuthConfigStatusUpdater_UnmatchingAuthConfigLabels(t *testing.T) {
	authConfig := newTestAuthConfig(map[string]string{"authorino.3scale.net/managed-by": "other"})
	resourceName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
	client := newTestK8sClient(&authConfig)
	reconciler := newStatusUpdaterReconciler(client)
	reconciler.LabelSelector = ToLabelSelector("authorino.3scale.net/managed-by=authorino")

	result, err := reconciler.Reconcile(context.Background(), controllerruntime.Request{NamespacedName: resourceName})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := v1beta1.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, !authConfigCheck.Status.Ready)
}
