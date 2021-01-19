package authorization

import (
	"github.com/3scale/authorino/pkg/common"
)

type JWTClaims struct {
	Enabled bool                         `yaml:"enabled,omitempty"`
	Match   map[string]map[string]string `yaml:"match"`  // TODO: implement
	Claims  map[string]string            `yaml:"claims"` // TODO: implement
}

func (self *JWTClaims) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type Alias JWTClaims
	a := Alias{Enabled: true}
	err := unmarshal(&a)
	if err != nil {
		return err
	}
	*self = JWTClaims(a)
	return nil
}

func (self *JWTClaims) Call(ctx common.AuthContext) (bool, error) {
	if !self.Enabled {
		return true, nil
	}

	return true, nil // TODO: Implement
}
