package identity

import (
	"context"

	"github.com/kuadrant/authorino/pkg/auth"
)

type MTLS struct {
	auth.AuthCredentials

	PEM string `yaml:"pem"`
}

func (self *MTLS) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	return "Authenticated with mTLS", nil // TODO: implement
}
