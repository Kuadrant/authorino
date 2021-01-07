package identity

import (
	"github.com/3scale-labs/authorino/pkg/config/internal"
)

type HMAC struct {
	Secret string `yaml:"secret"`
}

func (self *HMAC) Call(ctx internal.AuthContext) (interface{}, error) {
	return "Authenticated with HMAC", nil // TODO: implement
}
