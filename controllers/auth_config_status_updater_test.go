package controllers

import (
	"context"
	"testing"

	"github.com/kuadrant/authorino/api/v1beta1"

	"gotest.tools/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestAuthConfigStatusUpdaterReconcile(t *testing.T) {
	authConfig := v1beta1.AuthConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AuthConfig",
			APIVersion: "config.authorino.3scale.net/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-config-1",
			Namespace: "authorino",
		},
		Spec: v1beta1.AuthConfigSpec{
			Hosts: []string{"echo-api"},
		},
		Status: v1beta1.AuthConfigStatus{
			Ready: false,
		},
	}

	// Create a fake client with an auth config
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	client := fake.NewFakeClientWithScheme(scheme, &authConfig)

	resourceName := types.NamespacedName{
		Namespace: authConfig.Namespace,
		Name:      authConfig.Name,
	}

	result, err := (&AuthConfigStatusUpdater{
		Client: client,
	}).Reconcile(context.Background(), controllerruntime.Request{
		NamespacedName: resourceName,
	})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	authConfigCheck := v1beta1.AuthConfig{}
	_ = client.Get(context.TODO(), resourceName, &authConfigCheck)
	assert.Check(t, authConfigCheck.Status.Ready)
}
