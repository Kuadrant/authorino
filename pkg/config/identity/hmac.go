package identity

import (
	"context"

	"github.com/3scale-labs/authorino/pkg/common"
)

type HMAC struct {
	Secret string `yaml:"secret"`
}

func (self *HMAC) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	return "Authenticated with HMAC", nil // TODO: implement
}
