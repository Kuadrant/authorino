package controllers

import (
	"strings"
	"unicode"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type WatchedObject interface {
	GetLabels() map[string]string
}

func Watched(object WatchedObject, selector map[string]string) bool {
	labels := object.GetLabels()

	for key, value := range selector {
		if _, ok := labels[key]; !ok || labels[key] != value {
			return false
		}
	}

	return true
}

func FilterByLabels(selector map[string]string) predicate.Funcs {
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

func ToLabelSelectors(selectors string) map[string]string {
	lastQuote := rune(0)
	parseSelector := func(c rune) bool {
		switch {
		case c == lastQuote:
			lastQuote = rune(0)
			return false
		case lastQuote != rune(0):
			return false
		case unicode.In(c, unicode.Quotation_Mark):
			lastQuote = c
			return false
		default:
			return unicode.IsSpace(c)
		}
	}

	keysAndValues := strings.FieldsFunc(selectors, parseSelector)

	labels := make(map[string]string)
	for _, kv := range keysAndValues {
		parts := strings.Split(kv, "=")
		if len(parts) == 2 {
			value := parts[1]
			if unicode.In(rune(value[0]), unicode.Quotation_Mark) {
				value = value[1:]
			}
			if unicode.In(rune(value[len(value)-1]), unicode.Quotation_Mark) {
				value = value[:len(value)-1]
			}
			labels[parts[0]] = value
		}
	}
	return labels
}
