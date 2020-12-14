package config

import (
	"fmt"

	"github.com/3scale/authorino/pkg/config/metadata"
	"github.com/3scale/authorino/pkg/config/internal"
)

type MetadataConfig struct {
	UserInfo metadata.UserInfo `yaml:"userinfo,omitempty"`
	UMA metadata.UMA `yaml:"uma,omitempty"`
}

func (self *MetadataConfig) Call(ctx internal.AuthContext) (interface{}, error) {
	t, _ := self.GetType()
	switch t {
		case "userinfo": return self.UserInfo.Call(ctx)
		case "uma": return self.UMA.Call(ctx)
		default: return "", fmt.Errorf("Invalid metadata config")
	}
}

func (self *MetadataConfig) GetType() (string, error) {
	switch {
		case self.UserInfo != metadata.UserInfo{}: return "userinfo", nil
		case self.UMA != metadata.UMA{}: return "uma", nil
		default: return "", fmt.Errorf("Invalid metadata config")
	}
}
