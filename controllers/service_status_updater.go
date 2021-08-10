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

// +kubebuilder:rbac:groups=config.authorino.3scale.net,resources=services/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;create;update

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
	service.Status.NumIdentitySources = int64(len(service.Spec.Identity))
	service.Status.NumMetadataSources = int64(len(service.Spec.Metadata))
	service.Status.NumAuthorizationPolicies = int64(len(service.Spec.Authorization))
	service.Status.NumResponseItems = int64(len(service.Spec.Response))

	issuingWristbands := false
	for _, responseConfig := range service.Spec.Response {
		if responseConfig.GetType() == configv1beta1.ResponseWristband {
			issuingWristbands = true
			break
		}
	}
	service.Status.FestivalWristbandEnabled = issuingWristbands

	return u.Status().Update(ctx, service)
}

func (u *ServiceStatusUpdater) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1beta1.Service{}).
		Complete(u)
}
