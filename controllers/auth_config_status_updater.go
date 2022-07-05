package controllers

import (
	"context"
	"fmt"

	api "github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/pkg/cache"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AuthConfigStatusUpdater updates the status of a newly reconciled auth config
type AuthConfigStatusUpdater struct {
	client.Client
	Logger        logr.Logger
	Cache         cache.Cache
	LabelSelector labels.Selector
}

// +kubebuilder:rbac:groups=authorino.kuadrant.io,resources=authconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;create;update

func (u *AuthConfigStatusUpdater) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := u.Logger.WithValues("authconfig/status", req.NamespacedName)

	authConfig := api.AuthConfig{}
	if err := u.Get(ctx, req.NamespacedName, &authConfig); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found (some error must have happened)
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&authConfig.ObjectMeta, u.LabelSelector) {
		// could not find the resouce: 404 Not found (resouce must have been deleted)
		// or the resource misses required labels (i.e. not to be watched by this controller)
		// skip status update
		return ctrl.Result{}, nil
	} else {
		// resource found and it is to be watched by this controller
		// we need to update its status
		if err := u.updateAuthConfigStatus(ctx, req.String(), &authConfig); err != nil {
			logger.Info(err.Error())
			return ctrl.Result{Requeue: true}, nil
		} else {
			logger.Info("resource status updated")
			return ctrl.Result{}, nil
		}
	}
}

func (u *AuthConfigStatusUpdater) updateAuthConfigStatus(ctx context.Context, cacheId string, authConfig *api.AuthConfig) error {
	if len(u.Cache.FindKeys(cacheId)) != len(authConfig.Spec.Hosts) {
		authConfig.Status.Ready = false
		_ = u.Status().Update(ctx, authConfig)
		return fmt.Errorf("resource not ready")
	}

	authConfig.Status.Ready = true
	authConfig.Status.NumIdentitySources = int64(len(authConfig.Spec.Identity))
	authConfig.Status.NumMetadataSources = int64(len(authConfig.Spec.Metadata))
	authConfig.Status.NumAuthorizationPolicies = int64(len(authConfig.Spec.Authorization))
	authConfig.Status.NumResponseItems = int64(len(authConfig.Spec.Response))

	issuingWristbands := false
	for _, responseConfig := range authConfig.Spec.Response {
		if responseConfig.GetType() == api.ResponseWristband {
			issuingWristbands = true
			break
		}
	}
	authConfig.Status.FestivalWristbandEnabled = issuingWristbands

	return u.Status().Update(ctx, authConfig)
}

func (u *AuthConfigStatusUpdater) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.AuthConfig{}, builder.WithPredicates(LabelSelectorPredicate(u.LabelSelector))).
		Complete(u)
}
