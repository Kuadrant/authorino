package response

import (
	"context"
	"encoding/json"

	"github.com/kuadrant/authorino/pkg/common"

	"github.com/tidwall/gjson"
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
		if value.Pattern != "" {
			obj[property.Name] = gjson.Get(authJSON, value.Pattern).String()
		} else {
			obj[property.Name] = value.Static
		}
	}

	return obj, nil
}
