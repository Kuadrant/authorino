package identity

import (
	"context"

	"github.com/3scale-labs/authorino/pkg/common"
)

type MTLS struct {
	PEM string `yaml:"pem"`
}

func (self *MTLS) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	return "Authenticated with mTLS", nil // TODO: implement
}
