package controllers

import (
	"context"

	controller_builder "github.com/kuadrant/authorino/controllers/builder"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/index"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/trace"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
	ctx, span := trace.NewSpan(ctx, "secret", "secret.reconcile")
	defer span.End()

	span.SetAttributes(
		attribute.String("secret.namespace", req.Namespace),
		attribute.String("secret.name", req.Name),
	)

	logger := r.Logger.WithValues("secret", req.NamespacedName)

	secret := v1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found, some error must have happened
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get secret")
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&secret.ObjectMeta, r.LabelSelector) {
		// could not find the resource (404 Not found, resource must have been deleted)
		// or the resource is no longer to be watched (labels no longer match)
		// => delete the K8s Secret-based identity from all AuthConfigs
		span.AddEvent("secret.deleted_or_unwatched")
		authConfigs := r.getAuthConfigsWithK8sSecretBasedIdentity()
		span.SetAttributes(attribute.Int("secret.affected_authconfigs", len(authConfigs)))

		for authConfig := range authConfigs {
			r.revokeK8sSecretBasedIdentity(ctx, authConfig, req.NamespacedName)
		}
		span.AddEvent("secret.revoked_from_authconfigs")
	} else {
		// resource found => if the K8s Secret labels match, update all AuthConfigs
		span.AddEvent("secret.found")
		authConfigs := r.getAuthConfigsWithK8sSecretBasedIdentity()
		span.SetAttributes(attribute.Int("secret.affected_authconfigs", len(authConfigs)))

		for authConfig := range authConfigs {
			r.refreshK8sSecretBasedIdentity(ctx, authConfig, secret)
		}
		span.AddEvent("secret.refreshed_in_authconfigs")
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
	ctx, span := trace.NewSpan(ctx, "secret", "secret.revoke_identity")
	defer span.End()

	authConfigName := authConfigName(authConfig)
	span.SetAttributes(
		attribute.String("authconfig.name", authConfigName),
		attribute.String("secret.namespace", deleted.Namespace),
		attribute.String("secret.name", deleted.Name),
	)

	revokeCount := 0
	for _, identityEvaluator := range authConfig.IdentityConfigs {
		if ev, ok := identityEvaluator.(auth.K8sSecretBasedIdentityConfigEvaluator); ok {
			log.FromContext(ctx).V(1).Info("deleting k8s secret from the index", "authconfig", authConfigName)
			ev.RevokeK8sSecretBasedIdentity(ctx, deleted)
			revokeCount++
		}
	}

	span.SetAttributes(attribute.Int("secret.revoke_count", revokeCount))
	if revokeCount > 0 {
		span.AddEvent("secret.identities_revoked")
	} else {
		span.AddEvent("secret.no_identities_to_revoke")
	}
}

func (r *SecretReconciler) refreshK8sSecretBasedIdentity(ctx context.Context, authConfig *evaluators.AuthConfig, secret v1.Secret) {
	ctx, span := trace.NewSpan(ctx, "secret", "secret.refresh_identity")
	defer span.End()

	authConfigName := authConfigName(authConfig)
	span.SetAttributes(
		attribute.String("authconfig.name", authConfigName),
		attribute.String("secret.namespace", secret.Namespace),
		attribute.String("secret.name", secret.Name),
	)

	baseLogger := log.FromContext(ctx).WithValues("authconfig", authConfigName).V(1)
	addedCount := 0
	revokedCount := 0

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
				addedCount++
			} else {
				logger.Info("deleting k8s secret from the index")
				ev.RevokeK8sSecretBasedIdentity(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name})
				revokedCount++
			}
		}
	}

	span.SetAttributes(
		attribute.Int("secret.added_count", addedCount),
		attribute.Int("secret.revoked_count", revokedCount),
	)

	if addedCount > 0 {
		span.AddEvent("secret.identities_added")
	}
	if revokedCount > 0 {
		span.AddEvent("secret.identities_revoked")
	}
}

func authConfigName(authConfig *evaluators.AuthConfig) string {
	return types.NamespacedName{Namespace: authConfig.Labels["namespace"], Name: authConfig.Labels["authconfig"]}.String()
}
