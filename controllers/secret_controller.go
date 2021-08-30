package controllers

import (
	"context"
	"reflect"

	"github.com/kuadrant/authorino/api/v1beta1"
	configv1beta1 "github.com/kuadrant/authorino/api/v1beta1"
	controller_builder "github.com/kuadrant/authorino/controllers/builder"
	"github.com/kuadrant/authorino/pkg/common"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Supporting mocking out functions for testing
var newController = controller_builder.NewControllerManagedBy

// SecretReconciler reconciles k8s Secret objects
type SecretReconciler struct {
	client.Client
	Log                  logr.Logger
	Scheme               *runtime.Scheme
	SecretLabel          string
	AuthConfigReconciler reconcile.Reconciler
}

// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("secret", req.NamespacedName)

	var reconcile func(configv1beta1.AuthConfig)

	secret := v1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, &secret); err != nil && !errors.IsNotFound(err) {
		// could not get the secret but not because of a 404 Not found (some error must have happened)
		return ctrl.Result{}, err

	} else if errors.IsNotFound(err) {
		// could not find the secret: 404 Not found (secret must have been deleted)
		// try to find a secret with same name by digging into the cache of auth configs
		reconcile = func(authConfig configv1beta1.AuthConfig) {
			for _, host := range authConfig.Spec.Hosts {
				sr, _ := r.AuthConfigReconciler.(*AuthConfigReconciler)
				for _, id := range sr.Cache.Get(host).IdentityConfigs {
					i, _ := id.(common.APIKeySecretFinder)
					if s := i.FindSecretByName(req.NamespacedName); s != nil {
						r.reconcileAuthConfig(ctx, authConfig)
						return
					}
				}
			}
		}

	} else {
		// found the secret

		// return if not an Authorino-watched secret
		if _, watched := secret.Labels[r.SecretLabel]; !watched {
			return ctrl.Result{}, nil
		}

		// straightforward – if the API key labels match, reconcile the auth config
		reconcile = func(authConfig configv1beta1.AuthConfig) {
			for _, id := range authConfig.Spec.Identity {
				if id.GetType() == v1beta1.IdentityApiKey && reflect.DeepEqual(id.APIKey.LabelSelectors, secret.Labels) {
					r.reconcileAuthConfig(ctx, authConfig)
					return
				}
			}
		}
	}

	if err := r.reconcileAuthConfigsUsingAPIKey(ctx, req.Namespace, reconcile); err != nil {
		log.Info("could not reconcile auth configs", "req", req)
		return ctrl.Result{}, err
	} else {
		return ctrl.Result{}, nil
	}
}

func filterByLabels(secretLabel string) predicate.Funcs {
	filter := func(object client.Object) bool {
		_, ok := object.GetLabels()[secretLabel]
		return ok
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return filter(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return filter(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return filter(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return filter(e.Object)
		},
	}
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return newController(mgr).
		For(&v1.Secret{}).
		WithEventFilter(filterByLabels(r.SecretLabel)).
		Complete(r)
}

func (r *SecretReconciler) getAuthConfigsUsingAPIKey(ctx context.Context, namespace string) ([]configv1beta1.AuthConfig, error) {
	var existingAuthConfigs = &configv1beta1.AuthConfigList{}
	selectedAuthConfigs := make([]configv1beta1.AuthConfig, 0)

	if err := r.List(ctx, existingAuthConfigs, &client.ListOptions{
		Namespace: namespace,
	}); err != nil {
		return nil, err
	} else {
		for _, authConfig := range existingAuthConfigs.Items {
			for _, id := range authConfig.Spec.Identity {
				if id.GetType() == v1beta1.IdentityApiKey {
					selectedAuthConfigs = append(selectedAuthConfigs, authConfig)
					break
				}
			}
		}
		return selectedAuthConfigs, nil
	}
}

// reconcileAuthConfigsUsingAPIKey invokes the reconcile(authConfig) func asynchronously, for each authConfig using API key identity
func (r *SecretReconciler) reconcileAuthConfigsUsingAPIKey(ctx context.Context, namespace string, reconcile func(configv1beta1.AuthConfig)) error {
	if authConfigs, err := r.getAuthConfigsUsingAPIKey(ctx, namespace); err != nil {
		return err
	} else {
		for _, authConfig := range authConfigs {
			s := authConfig
			go func() {
				reconcile(s)
			}()
		}
		return nil
	}
}

func (r *SecretReconciler) reconcileAuthConfig(ctx context.Context, authConfig configv1beta1.AuthConfig) {
	_, _ = r.AuthConfigReconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: authConfig.Namespace,
			Name:      authConfig.Name,
		},
	})
}
