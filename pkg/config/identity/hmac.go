package identity

import "github.com/3scale-labs/authorino/pkg/config/common"

type HMAC struct {
	Secret string `yaml:"secret"`
}

func (self *HMAC) Call(ctx common.AuthContext) (interface{}, error) {
	return "Authenticated with HMAC", nil // TODO: implement
}
