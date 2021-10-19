package config

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config/metadata"
)

const (
	metadataUserInfo    = "METADATA_USERINFO"
	metadataUMA         = "METADATA_UMA"
	metadataGenericHTTP = "METADATA_GENERIC_HTTP"
)

var (
	// MetadataEvaluator represents the metadataStruct implementing its Call method
	MetadataEvaluator common.AuthConfigEvaluator
)

type MetadataConfig struct {
	Name        string                `yaml:"name"`
	UserInfo    *metadata.UserInfo    `yaml:"userinfo,omitempty"`
	UMA         *metadata.UMA         `yaml:"uma,omitempty"`
	GenericHTTP *metadata.GenericHttp `yaml:"http,omitempty"`
}

func init() {
	MetadataEvaluator = &MetadataConfig{}
}

func (config *MetadataConfig) Call(pipeline common.AuthPipeline, ctx context.Context, parentLogger log.Logger) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator != nil {
		return evaluator.Call(pipeline, ctx, parentLogger.WithName("metadata"))
	} else {
		return nil, fmt.Errorf("invalid metadata config")
	}
}

func (config *MetadataConfig) GetType() (string, error) {
	switch {
	case config.UserInfo != nil:
		return metadataUserInfo, nil
	case config.UMA != nil:
		return metadataUMA, nil
	case config.GenericHTTP != nil:
		return metadataGenericHTTP, nil
	default:
		return "", fmt.Errorf("invalid metadata config")
	}
}

func (config *MetadataConfig) GetAuthConfigEvaluator() common.AuthConfigEvaluator {
	t, _ := config.GetType()
	switch t {
	case metadataUserInfo:
		return config.UserInfo
	case metadataUMA:
		return config.UMA
	case metadataGenericHTTP:
		return config.GenericHTTP
	default:
		return nil
	}
}

func (config *MetadataConfig) GetName() string {
	return config.Name
}
