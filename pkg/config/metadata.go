package config

import (
	"fmt"

	"github.com/3scale-labs/authorino/pkg/config/common"
	"github.com/3scale-labs/authorino/pkg/config/metadata"
)

var (
	// MetadataEvaluator represents the metadataStruct implementing its Call method
	MetadataEvaluator common.AuthConfigEvaluator
)

type MetadataConfig struct {
	UserInfo *metadata.UserInfo `yaml:"userinfo,omitempty"`
	UMA      *metadata.UMA      `yaml:"uma,omitempty"`
}

func init() {
	MetadataEvaluator = &MetadataConfig{}
}

func (config *MetadataConfig) Call(ctx common.AuthContext) (interface{}, error) {
	t, _ := config.GetType()
	switch t {
	case "userinfo":
		return config.UserInfo.Call(ctx)
	case "uma":
		return config.UMA.Call(ctx)
	default:
		return "", fmt.Errorf("invalid metadata config")
	}
}

func (config *MetadataConfig) GetType() (string, error) {
	switch {
	case config.UserInfo != nil:
		return "userinfo", nil
	case config.UMA != nil:
		return "uma", nil
	default:
		return "", fmt.Errorf("invalid metadata config")
	}
}
