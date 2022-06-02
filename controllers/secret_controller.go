package controllers

import (
	"context"

	controller_builder "github.com/kuadrant/authorino/controllers/builder"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/log"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Supporting mocking out functions for testing
var newController = controller_builder.NewControllerManagedBy

type authConfigSet map[*evaluators.AuthConfig]struct{}

// SecretReconciler reconciles k8s Secret objects
type SecretReconciler struct {
	client.Client
	Logger        logr.Logger
	Scheme        *runtime.Scheme
	Cache         cache.Cache
	LabelSelector labels.Selector
	Namespace     string
}

// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("secret", req.NamespacedName)

	var reconcile func(*evaluators.AuthConfig)
	var c chan error

	secret := v1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, &secret); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found, some error must have happened
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&secret.ObjectMeta, r.LabelSelector) {
		// could not find the resource (404 Not found, resource must have been deleted)
		// or the resource is no longer to be watched (labels no longer match)
		// => delete the API key from all AuthConfigs
		reconcile = func(authConfig *evaluators.AuthConfig) {
			c <- r.deleteAPIKey(ctx, authConfig, req.NamespacedName)
		}
	} else {
		// resource found => if the API key labels match, update all AuthConfigs
		reconcile = func(authConfig *evaluators.AuthConfig) {
			c <- r.updateAPIKey(ctx, authConfig, secret)
		}
	}

	for authConfig := range r.getAuthConfigsUsingAPIKey(ctx) {
		c = make(chan error)
		go reconcile(authConfig)
		if err := <-c; err != nil {
			return ctrl.Result{}, err
		}
	}

	logger.Info("resource reconciled")
	return ctrl.Result{}, nil
}

func (r *SecretReconciler) ClusterWide() bool {
	return r.Namespace == ""
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return newController(mgr).
		For(&v1.Secret{}, builder.WithPredicates(LabelSelectorPredicate(r.LabelSelector))).
		Complete(r)
}

func (r *SecretReconciler) getAuthConfigsUsingAPIKey(ctx context.Context) authConfigSet {
	authConfigs := make(authConfigSet)
	var s struct{}
	for _, authConfig := range r.Cache.List() {
		for _, identityEvaluator := range authConfig.IdentityConfigs {
			if _, ok := identityEvaluator.(auth.APIKeyIdentityConfigEvaluator); ok {
				authConfigs[authConfig] = s
				break
			}
		}
	}
	return authConfigs
}

func (r *SecretReconciler) deleteAPIKey(ctx context.Context, authConfig *evaluators.AuthConfig, deleted types.NamespacedName) error {
	for _, identityEvaluator := range authConfig.IdentityConfigs {
		if ev, ok := identityEvaluator.(auth.APIKeyIdentityConfigEvaluator); ok {
			log.FromContext(ctx).V(1).Info("deleting api key from cache", "authconfig", authConfigName(authConfig))
			ev.DeleteAPIKeySecret(ctx, deleted)
		}
	}
	return r.updateCache(ctx, authConfig)
}

func (r *SecretReconciler) updateAPIKey(ctx context.Context, authConfig *evaluators.AuthConfig, secret v1.Secret) error {
	for _, identityEvaluator := range authConfig.IdentityConfigs {
		if ev, ok := identityEvaluator.(auth.APIKeyIdentityConfigEvaluator); ok {
			selector, _ := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: ev.GetAPIKeyLabelSelectors()})
			if selector == nil || selector.Matches(labels.Set(secret.Labels)) {
				log.FromContext(ctx).V(1).Info("adding api key to cache", "authconfig", authConfigName(authConfig))
				ev.RefreshAPIKeySecret(ctx, secret)
			} else {
				log.FromContext(ctx).V(1).Info("deleting api key from cache", "authconfig", authConfigName(authConfig))
				ev.DeleteAPIKeySecret(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name})
			}
		}
	}
	return r.updateCache(ctx, authConfig)
}

func (r *SecretReconciler) updateCache(ctx context.Context, authConfig *evaluators.AuthConfig) error {
	cacheId := authConfigName(authConfig)
	logger := log.FromContext(ctx).WithValues("authconfig", cacheId)
	for _, host := range r.Cache.FindKeys(cacheId) {
		if err := r.Cache.Set(cacheId, host, *authConfig, true); err != nil {
			logger.Error(err, "failed to update the cache")
			return err
		}
	}
	logger.V(1).Info("cache updated")
	return nil
}

func authConfigName(authConfig *evaluators.AuthConfig) string {
	return types.NamespacedName{Namespace: authConfig.Labels["namespace"], Name: authConfig.Labels["name"]}.String()
}
