package service

import (
	"log"
	"io/ioutil"
	"gopkg.in/yaml.v2"

	"github.com/3scale/authorino/pkg/config"
)

// APIConfig holds the configuration of each protected API
type APIConfig struct {
	Enabled bool `yaml:"enabled,omitempty"`
	IdentityConfigs []config.IdentityConfig `yaml:"identity,omitempty"`
	MetadataConfigs []config.MetadataConfig `yaml:"metadata,omitempty"`
	AuthorizationConfigs []config.AuthorizationConfig `yaml:"authorization,omitempty"`
}

func (self *APIConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type Alias APIConfig
	a := Alias{ Enabled: true }
	err := unmarshal(&a)
	if err != nil { return err }
	*self = APIConfig(a)
	return nil
}

// ServiceConfig is the instance config, holding the collection of configs of all protected APIs
type ServiceConfig struct {
	APIs map[string]APIConfig
}

func (c *ServiceConfig) Load(filePath string) error {
	configData, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
		return err
	}
	if err := c.Parse(configData); err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}

func (c *ServiceConfig) Parse(data []byte) error {
	c.APIs = make(map[string]APIConfig)
	return yaml.Unmarshal(data, &c.APIs)
}
