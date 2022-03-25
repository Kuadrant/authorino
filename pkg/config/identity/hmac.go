package identity

import (
	"context"

	"github.com/kuadrant/authorino/pkg/auth"
)

type HMAC struct {
	auth.AuthCredentials

	Secret string `yaml:"secret"`
}

func (self *HMAC) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	return "Authenticated with HMAC", nil // TODO: implement
}
