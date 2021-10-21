package authorization

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
)

type JSONPatternMatching struct {
	Conditions []common.JSONPatternMatchingRule
	Rules      []common.JSONPatternMatchingRule
}

func (jsonAuth *JSONPatternMatching) Call(pipeline common.AuthPipeline, ctx context.Context) (bool, error) {
	data := pipeline.GetDataForAuthorization()
	dataJSON, _ := json.Marshal(data)
	dataStr := string(dataJSON)

	for _, condition := range jsonAuth.Conditions {
		if match, err := condition.EvaluateFor(dataStr); err != nil {
			return false, err
		} else if !match { // skip the policy if any of the conditions does not match
			return true, nil
		}
	}

	for _, rule := range jsonAuth.Rules {
		if authorized, err := rule.EvaluateFor(dataStr); err != nil {
			return false, err
		} else if !authorized {
			return false, fmt.Errorf(unauthorizedErrorMsg)
		}
	}

	return true, nil
}
