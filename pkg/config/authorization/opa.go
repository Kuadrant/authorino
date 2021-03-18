package authorization

import (
	"context"
	"crypto/md5"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"

	"github.com/open-policy-agent/opa/rego"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	policyTemplate = `package %s
import input.context.request.http as http_request
import input.auth.identity
import input.auth.metadata
path = split(trim_left(http_request.path, "/"), "/")
default allow = false
%s`

	policyUIDHashSeparator = "|"

	opaPolicyPrecompileErrorMsg = "Failed to precompile OPA policy"
	invalidOPAResponseErrorMsg  = "Invalid response from OPA policy evaluation"
	unauthorizedErrorMsg        = "Unauthorized"
)

var (
	opaLog = ctrl.Log.WithName("Authorino").WithName("ApiKey")
)

func NewOPAAuthorization(policyName string, rego string, nonce int) *OPA {
	o := &OPA{
		Rego:       rego,
		policyUID:  generatePolicyUID(policyName, rego, nonce),
		opaContext: context.TODO(),
	}
	if err := o.precompilePolicy(); err != nil {
		opaLog.Error(err, opaPolicyPrecompileErrorMsg, "secret", policyName)
		return nil
	} else {
		return o
	}
}

type OPA struct {
	Rego string `yaml:"rego"`

	opaContext context.Context
	policy     *rego.PreparedEvalQuery
	policyUID  string
}

func (opa *OPA) Call(authContext common.AuthContext, ctx context.Context) (bool, error) {
	options := rego.EvalInput(authContext.ToData())
	results, err := opa.policy.Eval(opa.opaContext, options)

	if err != nil {
		return false, err
	} else if len(results) == 0 {
		return false, fmt.Errorf(invalidOPAResponseErrorMsg)
	} else if allowed := results[0].Bindings["allowed"].(bool); !allowed {
		return false, fmt.Errorf(unauthorizedErrorMsg)
	} else {
		return true, nil
	}
}

func (opa *OPA) precompilePolicy() error {
	policyName := fmt.Sprintf(`authorino.authz["%s"]`, opa.policyUID)
	policyContent := fmt.Sprintf(policyTemplate, policyName, opa.Rego)
	regoQuery := rego.Query("allowed = data." + policyName + ".allow")
	regoModule := rego.Module(opa.policyUID+".rego", policyContent)

	if regoPolicy, err := rego.New(regoQuery, regoModule).PrepareForEval(opa.opaContext); err != nil {
		return err
	} else {
		opa.policy = &regoPolicy
		return nil
	}
}

func generatePolicyUID(policyName string, policyContent string, nonce int) string {
	data := []byte(fmt.Sprint(nonce) + policyUIDHashSeparator + policyName + policyUIDHashSeparator + policyContent)
	return fmt.Sprintf("%x", md5.Sum(data))
}
