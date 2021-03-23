package controllers

import (
	"context"
	"reflect"

	"github.com/3scale-labs/authorino/api/v1beta1"
	configv1beta1 "github.com/3scale-labs/authorino/api/v1beta1"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const authorinoWatchedSecretLabel = "authorino.3scale.net/managed-by"

// SecretReconciler reconciles k8s Secret objects
type SecretReconciler struct {
	client.Client
	Log               logr.Logger
	Scheme            *runtime.Scheme
	ServiceReconciler reconcile.Reconciler
}

func (r *SecretReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("secret", req.NamespacedName)

	secret := v1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, &secret); err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	// return if not an Authorino-watched secret
	if _, watched := secret.Labels[authorinoWatchedSecretLabel]; !watched {
		// FIXME: Authorino won't be able to fetch the secret's labels if the secret was deleted, so it will end up not reconciling the services anyway
		return ctrl.Result{}, nil
	}

	var serviceList = &configv1beta1.ServiceList{}
	if err := r.List(ctx, serviceList); err != nil {
		log.Info("could not fetch list of services", "object", req)
		return ctrl.Result{}, nil
	} else {
		for _, service := range serviceList.Items {
			for _, id := range service.Spec.Identity {
				if id.GetType() == v1beta1.IdentityApiKey && reflect.DeepEqual(id.APIKey.LabelSelectors, secret.Labels) {
					_, _ = r.ServiceReconciler.Reconcile(ctrl.Request{
						NamespacedName: types.NamespacedName{
							Namespace: service.Namespace,
							Name:      service.Name,
						},
					})
				}
			}
		}
	}

	return ctrl.Result{}, nil
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(r)
}
