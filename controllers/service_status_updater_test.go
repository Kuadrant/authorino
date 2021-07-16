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

func TestServiceStatusUpdaterReconcile(t *testing.T) {
	service := v1beta1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "config.authorino.3scale.net/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service1",
			Namespace: "authorino",
		},
		Spec: v1beta1.ServiceSpec{
			Hosts: []string{"echo-api"},
		},
		Status: v1beta1.ServiceStatus{
			Ready: false,
		},
	}

	// Create a fake client with a service
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	client := fake.NewFakeClientWithScheme(scheme, &service)

	resourceName := types.NamespacedName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}

	result, err := (&ServiceStatusUpdater{
		Client: client,
	}).Reconcile(context.Background(), controllerruntime.Request{
		NamespacedName: resourceName,
	})

	assert.Equal(t, result, ctrl.Result{})
	assert.NilError(t, err)

	serviceCheck := v1beta1.Service{}
	_ = client.Get(context.TODO(), resourceName, &serviceCheck)
	assert.Check(t, serviceCheck.Status.Ready)
}
