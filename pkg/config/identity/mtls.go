package identity

import (
	"github.com/3scale/authorino/pkg/common"
)

type MTLS struct {
	PEM string `yaml:"pem"`
}

func (self *MTLS) Call(ctx common.AuthContext) (interface{}, error) {
	return "Authenticated with mTLS", nil // TODO: implement
}
