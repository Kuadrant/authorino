package config

import (
	"fmt"

	"github.com/3scale-labs/authorino/pkg/config/common"
	"github.com/3scale-labs/authorino/pkg/config/metadata"
)

type MetadataConfig struct {
	UserInfo *metadata.UserInfo `yaml:"userinfo,omitempty"`
	UMA      *metadata.UMA      `yaml:"uma,omitempty"`
}

func (self *MetadataConfig) Call(ctx common.AuthContext) (interface{}, error) {
	t, _ := self.GetType()
	switch t {
	case "userinfo":
		return self.UserInfo.Call(ctx)
	case "uma":
		return self.UMA.Call(ctx)
	default:
		return "", fmt.Errorf("Invalid metadata config")
	}
}

func (self *MetadataConfig) GetType() (string, error) {
	switch {
	case self.UserInfo != nil:
		return "userinfo", nil
	case self.UMA != nil:
		return "uma", nil
	default:
		return "", fmt.Errorf("Invalid metadata config")
	}
}
