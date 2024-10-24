package response

import (
	"context"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/json"
)

func NewDynamicJSONResponse(properties []json.JSONProperty) *DynamicJSON {
	return &DynamicJSON{
		Properties: properties,
	}
}

type DynamicJSON struct {
	Properties []json.JSONProperty
}

func (j *DynamicJSON) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	obj := make(map[string]interface{})

	authJSON := pipeline.GetAuthorizationJSON()

	for _, property := range j.Properties {
		value := property.Value
		if resolved, err := value.ResolveFor(authJSON); err != nil {
			return nil, err
		} else {
			obj[property.Name] = resolved
		}
	}

	return obj, nil
}
