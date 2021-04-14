package config

import "github.com/3scale-labs/authorino/pkg/common"

// APIConfig holds the static configuration to be evaluated in the auth pipeline
type APIConfig struct {
	IdentityConfigs      []common.AuthConfigEvaluator `yaml:"identity,omitempty"`
	MetadataConfigs      []common.AuthConfigEvaluator `yaml:"metadata,omitempty"`
	AuthorizationConfigs []common.AuthConfigEvaluator `yaml:"authorization,omitempty"`
}

func (config *APIConfig) GetChallengeHeaders() []map[string]string {
	challengeHeaders := make([]map[string]string, 0)

	for _, idConfig := range config.IdentityConfigs {
		idEvaluator := idConfig.(common.IdentityConfigEvaluator)
		creds := idEvaluator.GetAuthCredentials()
		challengeHeaders = append(challengeHeaders, map[string]string{"WWW-Authenticate": creds.GetCredentialsKeySelector()})
	}

	return challengeHeaders
}
