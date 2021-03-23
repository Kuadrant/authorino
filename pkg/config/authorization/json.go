package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/3scale-labs/authorino/pkg/common"

	"github.com/tidwall/gjson"
)

const (
	operatorEq    = "eq"
	operatorNeq   = "neq"
	operatorIncl  = "incl"
	operatorExcl  = "excl"
	operatorRegex = "matches"

	unsupportedOperatorErrorMsg = "Unsupported operator for JSON authorization"
)

type JSONPatternMatchingRule struct {
	Selector string `yaml:"selector"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

type JSONPatternMatching struct {
	Conditions []JSONPatternMatchingRule `yaml:"conditions,omitempty"`
	Rules      []JSONPatternMatchingRule `yaml:"rules"`
}

func (jsonAuth *JSONPatternMatching) Call(authContext common.AuthContext, ctx context.Context) (bool, error) {
	data := authContext.GetDataForAuthorization()
	dataJSON, _ := json.Marshal(data)
	dataStr := string(dataJSON)

	for _, condition := range jsonAuth.Conditions {
		if match, err := evaluateRule(condition, dataStr); err != nil {
			return false, err
		} else if !match { // skip the policy if any of the conditions does not match
			return true, nil
		}
	}

	for _, rule := range jsonAuth.Rules {
		if authorized, err := evaluateRule(rule, dataStr); err != nil {
			return false, err
		} else if !authorized {
			return false, fmt.Errorf(unauthorizedErrorMsg)
		}
	}

	return true, nil
}

func evaluateRule(rule JSONPatternMatchingRule, jsonData string) (bool, error) {
	expectedValue := rule.Value
	obtainedValue := gjson.Get(jsonData, rule.Selector)

	switch rule.Operator {
	case operatorEq:
		return (expectedValue == obtainedValue.String()), nil

	case operatorNeq:
		return (expectedValue != obtainedValue.String()), nil

	case operatorIncl:
		for _, item := range obtainedValue.Array() {
			if expectedValue == item.String() {
				return true, nil
			}
		}
		return false, nil

	case operatorExcl:
		for _, item := range obtainedValue.Array() {
			if expectedValue == item.String() {
				return false, nil
			}
		}
		return true, nil

	case operatorRegex:
		if re, err := regexp.Compile(expectedValue); err != nil {
			return false, err
		} else {
			return re.MatchString(obtainedValue.String()), nil
		}

	default:
		return false, fmt.Errorf(unsupportedOperatorErrorMsg)
	}
}
