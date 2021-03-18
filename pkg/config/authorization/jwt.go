package authorization

import (
	"context"

	"github.com/3scale-labs/authorino/pkg/common"
)

type JWTClaims struct {
	Match  map[string]interface{} `yaml:"match"`  // TODO: implement
	Claims map[string]interface{} `yaml:"claims"` // TODO: implement
}

func (self *JWTClaims) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type Alias JWTClaims
	a := Alias{}
	err := unmarshal(&a)
	if err != nil {
		return err
	}
	*self = JWTClaims(a)
	return nil
}

func (self *JWTClaims) Call(authContext common.AuthContext, ctx context.Context) (bool, error) {
	return true, nil // TODO: Implement
}
