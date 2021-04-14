package config

import (
	"context"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/config/metadata"
)

var (
	// MetadataEvaluator represents the metadataStruct implementing its Call method
	MetadataEvaluator common.AuthConfigEvaluator
)

type MetadataConfig struct {
	Name     string             `yaml:"name"`
	UserInfo *metadata.UserInfo `yaml:"userinfo,omitempty"`
	UMA      *metadata.UMA      `yaml:"uma,omitempty"`
}

func init() {
	MetadataEvaluator = &MetadataConfig{}
}

func (config *MetadataConfig) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	t, _ := config.GetType()
	switch t {
	case "userinfo":
		return config.UserInfo.Call(pipeline, ctx)
	case "uma":
		return config.UMA.Call(pipeline, ctx)
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

func (config *MetadataConfig) GetName() string {
	return config.Name
}
