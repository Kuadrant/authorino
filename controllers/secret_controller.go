package controllers

import (
	"context"

	controller_builder "github.com/kuadrant/authorino/controllers/builder"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/index"
	"github.com/kuadrant/authorino/pkg/log"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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
	Index         index.Index
	LabelSelector labels.Selector
	Namespace     string
}

// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("secret", req.NamespacedName)

	secret := v1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found, some error must have happened
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&secret.ObjectMeta, r.LabelSelector) {
		// could not find the resource (404 Not found, resource must have been deleted)
		// or the resource is no longer to be watched (labels no longer match)
		// => delete the K8s Secret-based identity from all AuthConfigs
		r.eachAuthConfigsWithK8sSecretBasedIdentity(func(authConfig *evaluators.AuthConfig) {
			r.revokeK8sSecretBasedIdentity(ctx, authConfig, req.NamespacedName)
		})
	} else {
		// resource found => if the K8s Secret labels match, update all AuthConfigs
		r.eachAuthConfigsWithK8sSecretBasedIdentity(func(authConfig *evaluators.AuthConfig) {
			r.refreshK8sSecretBasedIdentity(ctx, authConfig, secret)
		})
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

func (r *SecretReconciler) eachAuthConfigsWithK8sSecretBasedIdentity(f func(*evaluators.AuthConfig)) {
	for authConfig := range r.getAuthConfigsWithK8sSecretBasedIdentity() {
		f(authConfig)
	}
}

func (r *SecretReconciler) getAuthConfigsWithK8sSecretBasedIdentity() authConfigSet {
	authConfigs := make(authConfigSet)
	var s struct{}
	for _, authConfig := range r.Index.List() {
		for _, identityEvaluator := range authConfig.IdentityConfigs {
			if _, ok := identityEvaluator.(auth.K8sSecretBasedIdentityConfigEvaluator); ok {
				authConfigs[authConfig] = s
				break
			}
		}
	}
	return authConfigs
}

func (r *SecretReconciler) revokeK8sSecretBasedIdentity(ctx context.Context, authConfig *evaluators.AuthConfig, deleted types.NamespacedName) {
	for _, identityEvaluator := range authConfig.IdentityConfigs {
		if ev, ok := identityEvaluator.(auth.K8sSecretBasedIdentityConfigEvaluator); ok {
			log.FromContext(ctx).V(1).Info("deleting k8s secret from the index", "authconfig", authConfigName(authConfig))
			ev.RevokeK8sSecretBasedIdentity(ctx, deleted)
		}
	}
}

func (r *SecretReconciler) refreshK8sSecretBasedIdentity(ctx context.Context, authConfig *evaluators.AuthConfig, secret v1.Secret) {
	baseLogger := log.FromContext(ctx).WithValues("authconfig", authConfigName(authConfig)).V(1)
	for _, identityEvaluator := range authConfig.IdentityConfigs {
		logger := baseLogger
		if logger.Enabled() {
			if ev, ok := identityEvaluator.(auth.NamedEvaluator); ok {
				logger = baseLogger.WithValues("config", ev.GetName())
			}
		}
		if ev, ok := identityEvaluator.(auth.K8sSecretBasedIdentityConfigEvaluator); ok {
			selector := ev.GetK8sSecretLabelSelectors()
			if selector == nil || selector.Matches(labels.Set(secret.Labels)) {
				logger.Info("adding k8s secret to the index")
				ev.AddK8sSecretBasedIdentity(ctx, secret)
			} else {
				logger.Info("deleting k8s secret from the index")
				ev.RevokeK8sSecretBasedIdentity(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name})
			}
		}
	}
}

func authConfigName(authConfig *evaluators.AuthConfig) string {
	return types.NamespacedName{Namespace: authConfig.Labels["namespace"], Name: authConfig.Labels["authconfig"]}.String()
}
