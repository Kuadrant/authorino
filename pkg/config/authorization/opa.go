package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/3scale-labs/authorino/pkg/config/common"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/open-policy-agent/opa/rego"
)

type OPA struct {
	Enabled    bool   `yaml:"enabled,omitempty"`
	UUID       string `yaml:"uuid"`
	Rego       string `yaml:"rego"`
	opaContext context.Context
	policy     *rego.PreparedEvalQuery
}

func (self *OPA) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type Alias OPA
	a := Alias{Enabled: true}
	err := unmarshal(&a)
	if err != nil {
		return err
	}
	*self = OPA(a)
	err = self.Prepare()
	if err != nil {
		return fmt.Errorf("opa: failed to prepare inline Rego policy %v", self.policyName())
	}
	return nil
}

const (
	policyTemplate = `package %s
import input.attributes.request.http as http_request
import input.context.identity
import input.context.metadata
path = split(trim_left(http_request.path, "/"), "/")
default allow = false
%s`
)

func (self *OPA) Prepare() error {
	regoPolicy := fmt.Sprintf(policyTemplate, self.policyName(), self.Rego)

	self.opaContext = context.TODO()

	regoQuery := rego.Query("allowed = data." + self.policyName() + ".allow")
	regoModule := rego.Module(self.UUID+".rego", regoPolicy)
	p, err := rego.New(regoQuery, regoModule).PrepareForEval(self.opaContext)
	if err != nil {
		return err
	}

	self.policy = &p

	log.Printf("[OPA] new policy registered: %v", self.policyName())

	return nil
}

func (self *OPA) policyName() string {
	return fmt.Sprintf(`authorino.authz["%s"]`, self.UUID)
}

type OPAInput struct {
	Request *auth.AttributeContext `json:"attributes"`
	Context map[string]interface{} `json:"context"`
}

func (self *OPAInput) ToJSON() ([]byte, error) {
	res, err := json.Marshal(&self)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (self *OPA) Call(ctx common.AuthContext) (bool, error) {
	if !self.Enabled {
		return true, nil
	}

	contextData := make(map[string]interface{})
	contextData["identity"] = ctx.GetIdentity()
	contextData["metadata"] = ctx.GetMetadata()

	input := OPAInput{
		Request: ctx.GetRequest().Attributes,
		Context: contextData,
	}

	inputJSON, err := input.ToJSON()
	if err != nil {
		return false, err
	}
	log.Printf("[OPA] input: %v", string(inputJSON))

	evalOption := rego.EvalInput(input)
	results, err := self.policy.Eval(self.opaContext, evalOption)

	if err != nil {
		return false, err
	} else if len(results) == 0 {
		return false, fmt.Errorf("opa: invalid response for policy %v", self.policyName())
	} else if allowed := results[0].Bindings["allowed"].(bool); !allowed {
		return false, fmt.Errorf("Unauthorized")
	} else {
		return true, nil
	}
}
