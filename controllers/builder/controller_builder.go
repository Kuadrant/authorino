package builder

import (
	"k8s.io/apimachinery/pkg/runtime"
	ctrlruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ControllerBuilder interface {
	For(runtime.Object, ...builder.ForOption) ControllerBuilder
	WithEventFilter(predicate.Predicate) ControllerBuilder
	Complete(reconcile.Reconciler) error
}

func NewControllerManagedBy(manager ctrlruntime.Manager) ControllerBuilder {
	return &builderWrapper{
		Builder: ctrlruntime.NewControllerManagedBy(manager),
	}
}

type builderWrapper struct {
	Builder *builder.Builder
}

func (bw *builderWrapper) For(object runtime.Object, opts ...builder.ForOption) ControllerBuilder {
	bw.Builder.For(object, opts...)
	return bw
}

func (bw *builderWrapper) WithEventFilter(p predicate.Predicate) ControllerBuilder {
	bw.Builder.WithEventFilter(p)
	return bw
}

func (bw *builderWrapper) Complete(r reconcile.Reconciler) error {
	return bw.Builder.Complete(r)
}
