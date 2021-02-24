package identity

import (
	"context"

	"github.com/3scale-labs/authorino/pkg/common"
)

type APIKey struct {
	SecretKey string `yaml:"secret_key"`
}

func (self *APIKey) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	return "Authenticated with API key", nil // TODO: implement
}
