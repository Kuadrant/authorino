package response

import (
	"context"
	"encoding/json"

	"github.com/kuadrant/authorino/pkg/common"
)

func NewDynamicJSONResponse(properties []common.JSONProperty) *DynamicJSON {
	return &DynamicJSON{
		Properties: properties,
	}
}

type DynamicJSON struct {
	Properties []common.JSONProperty
}

func (j *DynamicJSON) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	obj := make(map[string]interface{})

	authData, _ := json.Marshal(pipeline.GetPostAuthorizationData())
	authJSON := string(authData)

	for _, property := range j.Properties {
		value := property.Value
		obj[property.Name] = value.ResolveFor(authJSON)
	}

	return obj, nil
}
