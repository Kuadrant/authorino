package config

import (
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
)

// APIConfig holds the static configuration to be evaluated in the auth pipeline
type APIConfig struct {
	IdentityConfigs      []common.AuthConfigEvaluator `yaml:"identity,omitempty"`
	MetadataConfigs      []common.AuthConfigEvaluator `yaml:"metadata,omitempty"`
	AuthorizationConfigs []common.AuthConfigEvaluator `yaml:"authorization,omitempty"`
	ResponseConfigs      []common.AuthConfigEvaluator `yaml:"response,omitempty"`

	DenyWith
}

func (config *APIConfig) GetChallengeHeaders() []map[string]string {
	challengeHeaders := make([]map[string]string, 0)

	for _, authConfig := range config.IdentityConfigs {
		idConfig := authConfig.(*IdentityConfig)
		challenge := fmt.Sprintf("%v realm=\"%v\"", idConfig.GetAuthCredentials().GetCredentialsKeySelector(), idConfig.Name)
		challengeHeaders = append(challengeHeaders, map[string]string{"WWW-Authenticate": challenge})
	}

	return challengeHeaders
}

type DenyWith struct {
	Unauthenticated *DenyWithValues
	Unauthorized    *DenyWithValues
}

type DenyWithValues struct {
	Code    int32
	Message string
	Headers []common.JSONProperty
}
