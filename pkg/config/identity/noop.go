package identity

import (
	"context"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
)

type Noop struct {
	auth_credentials.AuthCredentials
}

type anonymousAccess struct {
	Anonymous bool `json:"anonymous"`
}

func (n *Noop) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	return &anonymousAccess{Anonymous: true}, nil
}
