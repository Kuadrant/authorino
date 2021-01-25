package identity

import (
	"github.com/3scale-labs/authorino/pkg/config/common"
)

type APIKey struct {
	SecretKey string `yaml:"secret_key"`
}

func (self *APIKey) Call(ctx common.AuthContext) (interface{}, error) {
	return "Authenticated with API key", nil // TODO: implement
}
