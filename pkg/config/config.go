package config

import "github.com/3scale-labs/authorino/pkg/common"

// APIConfig holds the configuration of each protected API
type APIConfig struct {
	Enabled              bool                         `yaml:"enabled,omitempty"`
	IdentityConfigs      []common.AuthConfigEvaluator `yaml:"identity,omitempty"`
	MetadataConfigs      []common.AuthConfigEvaluator `yaml:"metadata,omitempty"`
	AuthorizationConfigs []common.AuthConfigEvaluator `yaml:"authorization,omitempty"`
}

func (self *APIConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type Alias APIConfig
	a := Alias{Enabled: true}
	err := unmarshal(&a)
	if err != nil {
		return err
	}
	*self = APIConfig(a)
	return nil
}

// ServiceConfig is the instance config, holding the collection of configs of all protected APIs
type ServiceConfig struct {
	APIs map[string]APIConfig
}
