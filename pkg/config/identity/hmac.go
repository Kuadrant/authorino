package identity

import (
	"github.com/3scale/authorino/pkg/common"
)

type HMAC struct {
	Secret string `yaml:"secret"`
}

func (self *HMAC) Call(ctx common.AuthContext) (interface{}, error) {
	return "Authenticated with HMAC", nil // TODO: implement
}
