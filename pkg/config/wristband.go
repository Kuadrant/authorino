package config

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kuadrant/authorino/pkg/common"

	jwt "github.com/dgrijalva/jwt-go"
)

const WRISTBAND_LIFESPAN = 300

type Claims map[string]interface{}

func (c *Claims) Valid() error {
	return nil
}

func NewWristbandConfig(claims map[string]string) (*Wristband, error) {
	rng := rand.Reader
	key, err := rsa.GenerateKey(rng, 2048)

	if err != nil {
		return nil, err
	}

	customClaims := make(Claims)
	for claim, value := range claims{
		customClaims[claim] = value
	}

  return &Wristband{
		CustomClaims: customClaims,
		SigningKey: key,
	}, nil
}

type Wristband struct {
	CustomClaims Claims
	SigningKey *rsa.PrivateKey
}

func (w *Wristband) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	// resolved identity
	_, id := pipeline.GetResolvedIdentity()
	idStr, _ := json.Marshal(id)
	hash := sha256.New()
	hash.Write(idStr)
	sub := fmt.Sprintf("%x", hash.Sum(nil))

	// timestamps
	iat := time.Now().Unix()
  exp := iat + WRISTBAND_LIFESPAN

	// wristband claims
  claims := Claims{
		"iss": "authorino", // TODO: This needs to be replaced with an HTTP endpoint wherefrom an OpenID Connnect well-known config can be downloaded, including inside a`jwks_uri` claim that points to another HTTP endpoint where a JSON `{ "keys": [{ <w.SigningKey.PublicKey> }] }` can be obtained
		"iat": iat,
		"exp": exp,
		"sub": sub,
	}

	for claim, value := range w.CustomClaims {
		claims[claim] = value
	}

  token := jwt.NewWithClaims(jwt.SigningMethodRS256, &claims)

  if wristband, err := token.SignedString(w.SigningKey); err != nil {
		return nil, err
	} else {
		return wristband, nil
	}
}
