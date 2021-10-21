package authorization

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"

	"github.com/open-policy-agent/opa/rego"
)

const (
	policyTemplate = `package %s
default allow = false
%s`

	policyUIDHashSeparator = "|"

	opaPolicyPrecompileErrorMsg = "Failed to precompile OPA policy"
	regoDownloadErrorMsg        = "Failed to download Rego data"
	invalidOPAResponseErrorMsg  = "Invalid response from OPA policy evaluation"
)

func NewOPAAuthorization(policyName string, rego string, externalSource OPAExternalSource, nonce int, ctx context.Context) (*OPA, error) {
	logger := log.FromContext(ctx).WithName("opa")

	if rego == "" && externalSource.Endpoint != "" {
		downloadedRego, err := externalSource.downloadRegoDataFromUrl()
		if err != nil {
			logger.Error(err, regoDownloadErrorMsg, "secret", policyName)
			return nil, err
		}
		rego = downloadedRego
	}

	rego = cleanUpRegoDocument(rego)

	o := &OPA{
		Rego:              rego,
		OPAExternalSource: externalSource,
		policyUID:         generatePolicyUID(policyName, rego, nonce),
		opaContext:        context.TODO(),
	}
	if err := o.precompilePolicy(); err != nil {
		logger.Error(err, opaPolicyPrecompileErrorMsg, "secret", policyName)
		return nil, err
	} else {
		return o, nil
	}
}

type OPA struct {
	Rego              string `yaml:"rego"`
	OPAExternalSource OPAExternalSource

	opaContext context.Context
	policy     *rego.PreparedEvalQuery
	policyUID  string
}

func (opa *OPA) Call(pipeline common.AuthPipeline, ctx context.Context) (bool, error) {
	options := rego.EvalInput(pipeline.GetDataForAuthorization())
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

type responseOpaJson struct {
	Result resultJson `json:"result"`
}

type resultJson struct {
	Raw string `json:"raw"`
}

func cleanUpRegoDocument(rego string) string {
	r, _ := regexp.Compile("(\\s)*package.*[;\\n]+")
	return r.ReplaceAllString(rego, "")
}

type OPAExternalSource struct {
	Endpoint     string
	SharedSecret string
	auth_credentials.AuthCredentials
}

func (ext *OPAExternalSource) downloadRegoDataFromUrl() (string, error) {
	req, err := ext.BuildRequestWithCredentials(context.TODO(), ext.Endpoint, "GET", ext.SharedSecret, nil)
	if err != nil {
		return "", err
	}

	if resp, err := http.DefaultClient.Do(req); err != nil {
		return "", fmt.Errorf("failed to fetch Rego config: %v", err)
	} else {
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("unable to read response body: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("%s: %s", resp.Status, body)
		}

		result := string(body)
		//json
		if resp.Header["Content-Type"][0] == "application/json" {
			var jsonResponse responseOpaJson
			if err := json.Unmarshal(body, &jsonResponse); err != nil {
				return "", fmt.Errorf("unable to unmarshal json response: %v", err)
			}
			result = jsonResponse.Result.Raw
		}
		return result, nil
	}
}
