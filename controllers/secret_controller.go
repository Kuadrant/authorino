package controllers

import (
	"context"
	"reflect"

	"github.com/3scale-labs/authorino/api/v1beta1"
	configv1beta1 "github.com/3scale-labs/authorino/api/v1beta1"
	"github.com/3scale-labs/authorino/pkg/common"

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

	var reconcile func(configv1beta1.Service)

	secret := v1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, &secret); err != nil && !errors.IsNotFound(err) {
		// could not get the secret but not because of a 404 Not found (some error must have happened)
		return ctrl.Result{}, err

	} else if errors.IsNotFound(err) {
		// could not find the secret: 404 Not found (secret must have been deleted)
		// try to find a secret with same name by digging into the cache of services
		reconcile = func(service configv1beta1.Service) {
			for _, host := range service.Spec.Hosts {
				sr, _ := r.ServiceReconciler.(*ServiceReconciler)
				for _, id := range sr.Cache.Get(host).IdentityConfigs {
					i, _ := id.(common.APIKeySecretFinder)
					if s := i.FindSecretByName(req.NamespacedName); s != nil {
						r.reconcileService(service)
						return
					}
				}
			}
		}

	} else {
		// found the secret

		// return if not an Authorino-watched secret
		if _, watched := secret.Labels[authorinoWatchedSecretLabel]; !watched {
			return ctrl.Result{}, nil
		}

		// straightforward – if the API key labels match, reconcile the service
		reconcile = func(service configv1beta1.Service) {
			for _, id := range service.Spec.Identity {
				if id.GetType() == v1beta1.IdentityApiKey && reflect.DeepEqual(id.APIKey.LabelSelectors, secret.Labels) {
					r.reconcileService(service)
					return
				}
			}
		}
	}

	if err := r.reconcileServicesUsingAPIKey(ctx, reconcile); err != nil {
		log.Info("could not reconcile services", "req", req)
		return ctrl.Result{}, err
	} else {
		return ctrl.Result{}, nil
	}
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(r)
}

func (r *SecretReconciler) getServicesUsingAPIKey(ctx context.Context) ([]configv1beta1.Service, error) {
	var existingServices = &configv1beta1.ServiceList{}
	selectedServices := make([]configv1beta1.Service, 0)

	if err := r.List(ctx, existingServices); err != nil {
		return nil, err
	} else {
		for _, service := range existingServices.Items {
			for _, id := range service.Spec.Identity {
				if id.GetType() == v1beta1.IdentityApiKey {
					selectedServices = append(selectedServices, service)
					break
				}
			}
		}
		return selectedServices, nil
	}
}

// reconcileServicesUsingAPIKey invokes the reconcile(service) func asynchronously, for each service using API key identity
func (r *SecretReconciler) reconcileServicesUsingAPIKey(ctx context.Context, reconcile func(configv1beta1.Service)) error {
	if services, err := r.getServicesUsingAPIKey(ctx); err != nil {
		return err
	} else {
		for _, service := range services {
			s := service
			go func() {
				reconcile(s)
			}()
		}
		return nil
	}
}

func (r *SecretReconciler) reconcileService(service configv1beta1.Service) {
	_, _ = r.ServiceReconciler.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: service.Namespace,
			Name:      service.Name,
		},
	})
}
