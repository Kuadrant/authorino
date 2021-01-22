package identity

import (
	"github.com/3scale-labs/authorino/pkg/config/internal"
)

type MTLS struct {
	PEM string `yaml:"pem"`
}

func (self *MTLS) Call(ctx internal.AuthContext) (interface{}, error) {
	return "Authenticated with mTLS", nil // TODO: implement
}
