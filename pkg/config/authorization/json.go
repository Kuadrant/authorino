package authorization

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"

	"github.com/tidwall/gjson"
)

const (
	operatorEq   = "eq"
	operatorNeq  = "neq"
	operatorIncl = "incl"
	operatorExcl = "excl"

	unsupportedOperatorErrorMsg = "Unsupported operator for JSON authorization"
)

type JSONPatternMatchingRule struct {
	Selector string `yaml:"selector"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

type JSONPatternMatching struct {
	Rules []JSONPatternMatchingRule `yaml:"rules"`
}

func (jsonAuth *JSONPatternMatching) Call(authContext common.AuthContext, ctx context.Context) (bool, error) {
	data := authContext.ToData()
	dataJSON, _ := json.Marshal(data)
	dataStr := string(dataJSON)

	for _, rule := range jsonAuth.Rules {
		var authorized bool

		expectedValue := rule.Value
		obtainedValue := gjson.Get(dataStr, rule.Selector)

		switch rule.Operator {
		case operatorEq:
			authorized = expectedValue == obtainedValue.String()

		case operatorNeq:
			authorized = expectedValue != obtainedValue.String()

		case operatorIncl:
			authorized = false
			for _, item := range obtainedValue.Array() {
				if expectedValue == item.String() {
					authorized = true
					break
				}
			}

		case operatorExcl:
			authorized = true
			for _, item := range obtainedValue.Array() {
				if expectedValue == item.String() {
					authorized = false
					break
				}
			}

		default:
			return false, fmt.Errorf(unsupportedOperatorErrorMsg)
		}

		if !authorized {
			return false, fmt.Errorf(unauthorizedErrorMsg)
		}
	}

	return true, nil
}
