package controllers

import (
	"context"
	"fmt"
	"sort"
	"strings"

	api "github.com/kuadrant/authorino/api/v1beta3"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/trace"
	"github.com/kuadrant/authorino/pkg/utils"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
	k8score "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AuthConfigStatusUpdater updates the status of a newly reconciled auth config
type AuthConfigStatusUpdater struct {
	client.Client
	Logger        logr.Logger
	StatusReport  *StatusReportMap
	LabelSelector labels.Selector
}

// +kubebuilder:rbac:groups=authorino.kuadrant.io,resources=authconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;create;update

func (u *AuthConfigStatusUpdater) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, span := trace.NewSpan(ctx, "authconfig.status", "authconfig_status.reconcile")
	defer span.End()

	span.SetAttributes(
		attribute.String("authconfig.namespace", req.Namespace),
		attribute.String("authconfig.name", req.Name),
		attribute.String("authconfig.resource_id", req.String()),
	)

	logger := u.Logger.WithValues("authconfig", req.NamespacedName)

	authConfig := api.AuthConfig{}
	if err := u.Get(ctx, req.NamespacedName, &authConfig); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found (some error must have happened)
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get authconfig")
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&authConfig.ObjectMeta, u.LabelSelector) {
		// could not find the resource: 404 Not found (resource must have been deleted)
		// or the resource misses required labels (i.e. not to be watched by this controller)
		// skip status update
		span.AddEvent("authconfig.deleted_or_unwatched")
		return ctrl.Result{}, nil
	} else {
		// resource found and it is to be watched by this controller
		// we need to update its status
		span.AddEvent("authconfig.updating_status")
		if err := u.updateAuthConfigStatus(log.IntoContext(ctx, logger), req.String(), &authConfig); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to update status")
			return ctrl.Result{Requeue: true}, nil
		} else {
			return ctrl.Result{}, nil
		}
	}
}

func (u *AuthConfigStatusUpdater) updateAuthConfigStatus(ctx context.Context, resourceId string, authConfig *api.AuthConfig) (err error) {
	ctx, span := trace.NewSpan(ctx, "authconfig.status", "authconfig_status.update")
	defer span.End()

	span.SetAttributes(
		attribute.String("authconfig.resource_id", resourceId),
		attribute.String("authconfig.namespace", authConfig.Namespace),
		attribute.String("authconfig.name", authConfig.Name),
	)

	logger := log.FromContext(ctx)

	var reason, message string
	linkedHosts := []string{}
	report, reportAvailable := u.StatusReport.Get(resourceId)
	if reportAvailable {
		reason = report.Reason
		message = report.Message
		linkedHosts = report.LinkedHosts
		span.SetAttributes(
			attribute.String("authconfig.status_reason", reason),
			attribute.Int("authconfig.linked_hosts_count", len(linkedHosts)),
		)
	} else {
		span.AddEvent("authconfig.no_status_report_available")
	}
	looseHosts := utils.SubtractSlice(authConfig.Spec.Hosts, linkedHosts)

	span.SetAttributes(
		attribute.Int("authconfig.loose_hosts_count", len(looseHosts)),
		attribute.Int("authconfig.total_hosts_count", len(authConfig.Spec.Hosts)),
	)

	// available
	changed := updateStatusAvailable(authConfig, len(linkedHosts) > 0)
	if changed {
		span.AddEvent("authconfig.status_available_changed")
	}

	// ready
	ready := len(looseHosts) == 0 && reason == api.StatusReasonReconciled
	readyChanged := updateStatusReady(authConfig, ready, reason, message)
	changed = readyChanged || changed
	if readyChanged {
		span.AddEvent("authconfig.status_ready_changed", oteltrace.WithAttributes(attribute.Bool("ready", ready)))
	}

	// summary
	summaryChanged := updateStatusSummary(authConfig, linkedHosts)
	changed = summaryChanged || changed
	if summaryChanged {
		span.AddEvent("authconfig.status_summary_changed")
	}

	span.SetAttributes(attribute.Bool("authconfig.status_changed", changed))

	if !authConfig.Status.Ready() {
		err = fmt.Errorf("resource not ready")
		span.AddEvent("authconfig.not_ready")
	}

	if !changed {
		logger.V(1).Info("resource status did not change")
		span.AddEvent("authconfig.status_unchanged")
		return // to save an update request
	}

	logger.V(1).Info("resource status changed", "authconfig/status", authConfig.Status)
	span.AddEvent("authconfig.persisting_status")

	if updateErr := u.Status().Update(ctx, authConfig); updateErr != nil {
		logger.Error(updateErr, "failed to update the resource")
		span.RecordError(updateErr)
		span.SetStatus(codes.Error, "failed to persist status update")
		err = updateErr
		return
	}

	logger.Info("resource status updated")
	span.AddEvent("authconfig.status_persisted")

	return
}

func (u *AuthConfigStatusUpdater) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.AuthConfig{}, builder.WithPredicates(LabelSelectorPredicate(u.LabelSelector))).
		Complete(u)
}

func updateStatusConditions(currentConditions []api.AuthConfigStatusCondition, newCondition api.AuthConfigStatusCondition) ([]api.AuthConfigStatusCondition, bool) {
	newCondition.LastTransitionTime = metav1.Now()

	if currentConditions == nil {
		return []api.AuthConfigStatusCondition{newCondition}, true
	}

	for i, condition := range currentConditions {
		if condition.Type == newCondition.Type {
			if condition.Status == newCondition.Status {
				if condition.Reason == newCondition.Reason && condition.Message == newCondition.Message {
					return currentConditions, false
				}

				newCondition.LastTransitionTime = condition.LastTransitionTime
			}

			res := make([]api.AuthConfigStatusCondition, len(currentConditions))
			copy(res, currentConditions)
			res[i] = newCondition
			return res, true
		}
	}

	return append(currentConditions, newCondition), true
}

func updateStatusAvailable(authConfig *api.AuthConfig, available bool) (changed bool) {
	status := k8score.ConditionFalse
	reason := api.StatusReasonHostsNotLinked
	message := "No hosts linked to the resource"

	if available {
		status = k8score.ConditionTrue
		reason = api.StatusReasonHostsLinked
		message = ""
	}

	authConfig.Status.Conditions, changed = updateStatusConditions(authConfig.Status.Conditions, api.AuthConfigStatusCondition{
		Type:    api.StatusConditionAvailable,
		Status:  status,
		Reason:  reason,
		Message: utils.CapitalizeString(message),
	})

	return
}

func updateStatusReady(authConfig *api.AuthConfig, ready bool, reason, message string) (changed bool) {
	status := k8score.ConditionFalse

	if ready {
		status = k8score.ConditionTrue
		reason = api.StatusReasonReconciled
		message = ""
	} else if reason == "" {
		reason = api.StatusReasonUnknown
	}

	authConfig.Status.Conditions, changed = updateStatusConditions(authConfig.Status.Conditions, api.AuthConfigStatusCondition{
		Type:    api.StatusConditionReady,
		Status:  status,
		Reason:  reason,
		Message: utils.CapitalizeString(message),
	})

	return
}

func updateStatusSummary(authConfig *api.AuthConfig, newLinkedHosts []string) (changed bool) {
	current := authConfig.Status.Summary

	if len(newLinkedHosts) == 0 {
		newLinkedHosts = []string{}
	}

	numResponseItems := 0
	if authConfig.Spec.Response != nil {
		numResponseItems = len(authConfig.Spec.Response.Success.DynamicMetadata) + len(authConfig.Spec.Response.Success.Headers)
	}
	new := api.AuthConfigStatusSummary{
		Ready:                    authConfig.Status.Ready(),
		HostsReady:               newLinkedHosts,
		NumHostsReady:            fmt.Sprintf("%d/%d", len(newLinkedHosts), len(authConfig.Spec.Hosts)),
		NumIdentitySources:       int64(len(authConfig.Spec.Authentication)),
		NumMetadataSources:       int64(len(authConfig.Spec.Metadata)),
		NumAuthorizationPolicies: int64(len(authConfig.Spec.Authorization)),
		NumResponseItems:         int64(numResponseItems),
		FestivalWristbandEnabled: issuingWristbands(authConfig),
	}

	currentLinkedHosts := current.HostsReady
	sort.Strings(currentLinkedHosts)
	sort.Strings(newLinkedHosts)

	changed = new.Ready != current.Ready ||
		new.NumHostsReady != current.NumHostsReady ||
		strings.Join(currentLinkedHosts, ",") != strings.Join(newLinkedHosts, ",") ||
		new.NumIdentitySources != current.NumIdentitySources ||
		new.NumMetadataSources != current.NumMetadataSources ||
		new.NumAuthorizationPolicies != current.NumAuthorizationPolicies ||
		new.NumResponseItems != current.NumResponseItems ||
		new.FestivalWristbandEnabled != current.FestivalWristbandEnabled

	if changed {
		authConfig.Status.Summary = new
	}

	return
}

func issuingWristbands(authConfig *api.AuthConfig) bool {
	if authConfig.Spec.Response != nil {
		for _, responseConfig := range authConfig.Spec.Response.Success.Headers {
			if responseConfig.GetMethod() == api.WristbandAuthResponse {
				return true
			}
		}
		for _, responseConfig := range authConfig.Spec.Response.Success.DynamicMetadata {
			if responseConfig.GetMethod() == api.WristbandAuthResponse {
				return true
			}
		}
	}
	return false
}
