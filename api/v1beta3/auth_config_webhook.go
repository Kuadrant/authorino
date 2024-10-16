package v1beta3

import (
	ctrl "sigs.k8s.io/controller-runtime"
)

func (a *AuthConfig) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(a).
		Complete()
}
