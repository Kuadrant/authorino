package controllers

import (
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type WatchedObject interface {
	GetLabels() map[string]string
}

func Watched(object WatchedObject, selector labels.Selector) bool {
	return selector == nil || selector.Matches(labels.Set(object.GetLabels()))
}

func LabelSelectorPredicate(selector labels.Selector) predicate.Funcs {
	filter := func(object client.Object) bool {
		return Watched(object, selector)
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return filter(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return filter(e.ObjectNew) || filter(e.ObjectOld)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return filter(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return filter(e.Object)
		},
	}
}

func ToLabelSelector(s string) labels.Selector {
	if selector, err := labels.Parse(s); err != nil {
		return labels.NewSelector()
	} else {
		return selector
	}
}
