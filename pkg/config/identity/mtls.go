package identity

import (
	"context"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/common/auth_credentials"
)

type MTLS struct {
	auth_credentials.AuthCredentials

	PEM string `yaml:"pem"`
}

func (self *MTLS) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	return "Authenticated with mTLS", nil // TODO: implement
}
