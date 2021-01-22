package config

// APIConfig holds the configuration of each protected API
type APIConfig struct {
	Enabled              bool                  `yaml:"enabled,omitempty"`
	IdentityConfigs      []IdentityConfig      `yaml:"identity,omitempty"`
	MetadataConfigs      []MetadataConfig      `yaml:"metadata,omitempty"`
	AuthorizationConfigs []AuthorizationConfig `yaml:"authorization,omitempty"`
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
