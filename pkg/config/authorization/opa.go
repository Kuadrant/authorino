package authorization

import (
	"context"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"

	"github.com/open-policy-agent/opa/rego"
)

const (
	policyTemplate = `package %s
import input.context.request.http as http_request
import input.auth.identity
import input.auth.metadata
path = split(trim_left(http_request.path, "/"), "/")
default allow = false
%s`
)

type OPA struct {
	UUID       string `yaml:"uuid"`
	Rego       string `yaml:"rego"`
	opaContext context.Context
	policy     *rego.PreparedEvalQuery
}

func (opa *OPA) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type Alias OPA
	a := Alias{}
	err := unmarshal(&a)
	if err != nil {
		return err
	}
	*opa = OPA(a)
	err = opa.Prepare()
	if err != nil {
		return fmt.Errorf("opa: failed to prepare inline Rego policy %v", opa.policyName())
	}
	return nil
}

func (opa *OPA) Prepare() error {
	regoPolicy := fmt.Sprintf(policyTemplate, opa.policyName(), opa.Rego)

	opa.opaContext = context.TODO()

	regoQuery := rego.Query("allowed = data." + opa.policyName() + ".allow")
	regoModule := rego.Module(opa.UUID+".rego", regoPolicy)
	p, err := rego.New(regoQuery, regoModule).PrepareForEval(opa.opaContext)
	if err != nil {
		return err
	}

	opa.policy = &p

	return nil
}

func (opa *OPA) policyName() string {
	return fmt.Sprintf(`authorino.authz["%s"]`, opa.UUID)
}

func (opa *OPA) Call(authContext common.AuthContext, ctx context.Context) (bool, error) {
	evalOption := rego.EvalInput(authContext.ToData())
	results, err := opa.policy.Eval(opa.opaContext, evalOption)

	if err != nil {
		return false, err
	} else if len(results) == 0 {
		return false, fmt.Errorf("opa: invalid response for policy %v", opa.policyName())
	} else if allowed := results[0].Bindings["allowed"].(bool); !allowed {
		return false, fmt.Errorf("Unauthorized")
	} else {
		return true, nil
	}
}
