package evaluators

import (
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/json"
)

func NewIdentityExtension(name string, value expressions.Value, overwrite bool) IdentityExtension {
	property := json.JSONProperty{
		Name:  name,
		Value: value,
	}
	return IdentityExtension{
		JSONProperty: property,
		Overwrite:    overwrite,
	}
}

type IdentityExtension struct {
	json.JSONProperty
	Overwrite bool
}

func (i *IdentityExtension) ResolveFor(identityObject map[string]any, authJSON string) (interface{}, error) {
	if value, exists := identityObject[i.Name]; exists && !i.Overwrite {
		return value, nil
	}
	return i.Value.ResolveFor(authJSON)
}
