package v1beta2

import (
	ctrl "sigs.k8s.io/controller-runtime"
)

func (a *AuthConfig) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(a).
		Complete()
}
