package identity

import (
	"context"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
)

type HMAC struct {
	auth_credentials.AuthCredentials

	Secret string `yaml:"secret"`
}

func (self *HMAC) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	return "Authenticated with HMAC", nil // TODO: implement
}
