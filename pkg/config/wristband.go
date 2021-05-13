package config

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/kuadrant/authorino/pkg/common"

	jwt "github.com/dgrijalva/jwt-go"
	jose "gopkg.in/square/go-jose.v2"
)

const DEFAULT_WRISTBAND_DURATION = 300

func NewSigningKey(name string, algorithm string, singingKey []byte) (*jose.JSONWebKey, error) {
	signingKey := &jose.JSONWebKey{
		KeyID:     name,
		Algorithm: algorithm,
	}

	keyPEM, _ := pem.Decode(singingKey)

	switch strings.Split(keyPEM.Type, " ")[0] {
	case "EC":
		if key, err := jwt.ParseECPrivateKeyFromPEM(singingKey); err != nil {
			return nil, err
		} else {
			signingKey.Key = key
		}

	case "RSA":
		if key, err := jwt.ParseRSAPrivateKeyFromPEM(singingKey); err != nil {
			return nil, err
		} else {
			signingKey.Key = key
		}

	default:
		return nil, fmt.Errorf("invalid signing key algorithm")
	}

	return signingKey, nil
}

type Claims map[string]interface{}

func (c *Claims) Valid() error {
	return nil
}

func NewWristbandConfig(issuer string, claims map[string]string, tokenDuration *int64, signingKeys []jose.JSONWebKey) (*Wristband, error) {
	// custom claims
	customClaims := make(Claims)
	for claim, value := range claims {
		customClaims[claim] = value
	}

	// token duration
	var duration int64
	if tokenDuration != nil {
		duration = *tokenDuration
	} else {
		duration = DEFAULT_WRISTBAND_DURATION
	}

	// signing keys
	if len(signingKeys) == 0 {
		return nil, fmt.Errorf("missing at least one signing key")
	}

	return &Wristband{
		Issuer:        issuer,
		CustomClaims:  customClaims,
		TokenDuration: duration,
		SigningKeys:   signingKeys,
	}, nil
}

type Wristband struct {
	Issuer        string
	CustomClaims  Claims
	TokenDuration int64
	SigningKeys   []jose.JSONWebKey
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
	exp := iat + int64(w.TokenDuration)

	// claims
	claims := Claims{
		"iss": w.GetIssuer(),
		"iat": iat,
		"exp": exp,
		"sub": sub,
	}

	for claim, value := range w.CustomClaims {
		claims[claim] = value
	}

	// signing key
	signingKey := w.SigningKeys[0]

	token := jwt.NewWithClaims(jwt.GetSigningMethod(signingKey.Algorithm), &claims)
	token.Header["kid"] = signingKey.KeyID

	if wristband, err := token.SignedString(signingKey.Key); err != nil {
		return nil, err
	} else {
		return wristband, nil
	}
}

type oidcConfig struct {
	Issuer               string   `json:"issuer"`
	JWKSURI              string   `json:"jwks_uri"`
	SupportedSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
}

func (w *Wristband) GetIssuer() string {
	return w.Issuer
}

func (w *Wristband) OpenIDConfig() (string, error) {
	issuer := w.GetIssuer()
	config := &oidcConfig{
		Issuer:               issuer,
		JWKSURI:              fmt.Sprintf("%v/.well-known/openid-connect/certs", issuer),
		SupportedSigningAlgs: []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"},
	}

	if configJSON, err := json.Marshal(config); err != nil {
		return "", err
	} else {
		return string(configJSON), nil
	}
}

func (w *Wristband) JWKS() (string, error) {
	publicKeys := make([]jose.JSONWebKey, 0)

	for _, signingKey := range w.SigningKeys {
		publicKeys = append(publicKeys, signingKey.Public())
	}

	jwks := jose.JSONWebKeySet{
		Keys: publicKeys,
	}

	if encodedJWKS, err := json.Marshal(jwks); err != nil {
		return "", err
	} else {
		return string(encodedJWKS), nil
	}
}
