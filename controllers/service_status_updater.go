package controllers

import (
	"context"

	configv1beta1 "github.com/kuadrant/authorino/api/v1beta1"

	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ServiceStatusUpdater updates the status of a newly reconciled service
type ServiceStatusUpdater struct {
	client.Client
}

func (u *ServiceStatusUpdater) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	service := configv1beta1.Service{}
	err := u.Get(ctx, req.NamespacedName, &service)

	if err != nil && errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, u.updateServiceStatus(ctx, &service, true)
}

func (u *ServiceStatusUpdater) updateServiceStatus(ctx context.Context, service *configv1beta1.Service, ready bool) error {
	service.Status.Ready = ready
	service.Status.NumIdentityPolicies = int64(len(service.Spec.Identity))
	service.Status.NumMetadataPolicies = int64(len(service.Spec.Metadata))
	service.Status.NumAuthorizationPolicies = int64(len(service.Spec.Authorization))
	service.Status.FestivalWristbandEnabled = service.Spec.Wristband != nil
	return u.Status().Update(ctx, service)
}

func (u *ServiceStatusUpdater) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1beta1.Service{}).
		Complete(u)
}
