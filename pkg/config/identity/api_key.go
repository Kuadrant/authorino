package identity

import (
	"github.com/3scale/authorino/pkg/config/internal"
)

type APIKey struct {
	SecretKey string `yaml:"secret_key"`
}

func (self *APIKey) Call(ctx internal.AuthContext) (interface{}, error) {
	return "Authenticated with API key", nil // TODO: implement
}
