package identity

import (
	"context"

	"github.com/kuadrant/authorino/pkg/auth"
)

type Noop struct {
	auth.AuthCredentials
}

type anonymousAccess struct {
	Anonymous bool `json:"anonymous"`
}

func (n *Noop) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	return &anonymousAccess{Anonymous: true}, nil
}
