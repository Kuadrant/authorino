package authorization

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/cron"

	opaParser "github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

const (
	policyTemplate = `package %s
default allow = false
%s`
	policyUIDHashSeparator = "|"
	allowQuery             = "allow"

	opaPolicyPrecompileErrorMsg          = "failed to precompile policy"
	regoDownloadErrorMsg                 = "failed to download rego data"
	invalidOPAResponseErrorMsg           = "invalid response from policy evaluation"
	opaPolicyRefreshedFromRegistry       = "policy updated from external registry"
	opaPolicyFailedToRefreshFromRegistry = "failed to refresh policy from external registry"
)

func NewOPAAuthorization(policyName string, rego string, externalSource *OPAExternalSource, allValues bool, nonce int, ctx context.Context) (*OPA, error) {
	logger := log.FromContext(ctx).WithName("opa")

	pullFromRegistry := rego == "" && externalSource != nil && externalSource.Endpoint != ""

	if pullFromRegistry {
		if downloadedRego, err := externalSource.downloadRegoDataFromUrl(); err != nil {
			logger.Error(err, regoDownloadErrorMsg, "policy", policyName)
			return nil, err
		} else {
			rego = downloadedRego
		}
	}

	rego = cleanUpRegoDocument(rego)

	o := &OPA{
		Rego:           rego,
		ExternalSource: externalSource,
		AllValues:      allValues,
		policyName:     policyName,
		policyUID:      generatePolicyUID(policyName, rego, nonce),
		opaContext:     context.TODO(),
	}

	if err := o.precompilePolicy(); err != nil {
		logger.Error(err, opaPolicyPrecompileErrorMsg, "policy", policyName)
		return nil, err
	} else {
		if pullFromRegistry {
			externalSource.setupRefresher(log.IntoContext(ctx, logger), o)
		}

		return o, nil
	}
}

type OPA struct {
	Rego           string `yaml:"rego"`
	ExternalSource *OPAExternalSource
	AllValues      bool

	opaContext context.Context
	policy     *rego.PreparedEvalQuery
	policyName string
	policyUID  string
}

func (opa *OPA) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	var authJSON interface{}
	if err := json.Unmarshal([]byte(pipeline.GetAuthorizationJSON()), &authJSON); err != nil {
		return false, err
	} else {
		options := rego.EvalInput(authJSON)
		results, err := opa.policy.Eval(opa.opaContext, options)

		if err != nil {
			return nil, err
		} else if len(results) == 0 {
			return nil, fmt.Errorf(invalidOPAResponseErrorMsg)
		} else if allowed, ok := results[0].Bindings[allowQuery].(bool); !ok || !allowed {
			return nil, fmt.Errorf(unauthorizedErrorMsg)
		} else {
			return results[0].Bindings, nil
		}
	}
}

// Clean ensures the goroutine started by ExternalSource.setupRefresher is cleaned up
func (opa *OPA) Clean(_ context.Context) error {
	if opa.ExternalSource == nil {
		return nil
	}

	return opa.ExternalSource.cleanupRefresher()
}

func (opa *OPA) precompilePolicy() error {
	policyName := fmt.Sprintf(`authorino.authz["%s"]`, opa.policyUID)
	policyContent := fmt.Sprintf(policyTemplate, policyName, opa.Rego)
	policyFileName := opa.policyUID + ".rego"
	queryTemplate := `%s = object.get(data.` + policyName + `, "%s", null)`

	var module *opaParser.Module
	queries := []string{fmt.Sprintf(queryTemplate, allowQuery, allowQuery)}
	var err error

	if module, err = opaParser.ParseModule(policyFileName, policyContent); err != nil {
		return err
	}

	if opa.AllValues {
		rules := map[string]interface{}{allowQuery: nil}
		for _, rule := range module.Rules {
			name := string(rule.Head.Name)
			if _, found := rules[name]; !found {
				queries = append(queries, fmt.Sprintf(queryTemplate, name, name))
				rules[name] = nil
			}
		}
	}

	r := rego.New(
		rego.Query(strings.Join(queries, ";")),
		rego.ParsedModule(module),
	)

	if regoPolicy, err := r.PrepareForEval(opa.opaContext); err != nil {
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
	TTL       int
	refresher cron.Worker
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

func (ext *OPAExternalSource) setupRefresher(ctx context.Context, opa *OPA) {
	logger := log.FromContext(ctx).WithValues("endpoint", ext.Endpoint, "policy", opa.policyName)
	ext.refresher, _ = cron.StartWorker(ctx, ext.TTL, func() {
		if downloadedRego, err := ext.downloadRegoDataFromUrl(); err == nil {
			current := opa.Rego
			new := cleanUpRegoDocument(downloadedRego)
			if new != current {
				opa.Rego = new
				if err = opa.precompilePolicy(); err != nil {
					opa.Rego = current
					logger.Error(err, opaPolicyFailedToRefreshFromRegistry)
				} else {
					logger.Info(opaPolicyRefreshedFromRegistry)
				}
			}
		} else {
			logger.Error(err, opaPolicyFailedToRefreshFromRegistry)
		}
	})
}

func (ext *OPAExternalSource) cleanupRefresher() error {
	if ext.refresher == nil {
		return nil
	}
	return ext.refresher.Stop()
}
