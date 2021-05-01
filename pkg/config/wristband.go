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
	ctrl "sigs.k8s.io/controller-runtime"
)

const DEFAULT_WRISTBAND_DURATION = 300

var wristbandLogger = ctrl.Log.WithName("authorino").WithName("wristband")

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

func NewWristbandConfig(claims map[string]string, tokenDuration *int64, signingKeys []jose.JSONWebKey) (*Wristband, error) {
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

	wristband := &Wristband{
		CustomClaims:  customClaims,
		TokenDuration: duration,
		SigningKeys:   signingKeys,
	}

	if jwks, err := wristband.JWKS(); err != nil { // TODO: Move to HTTP service (jwks_uri)
		wristbandLogger.Error(err, "could not generate jwks")
	} else {
		wristbandLogger.Info("signing festival wristbands", "jwks", jwks)
	}

	return wristband, nil
}

type Wristband struct {
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
		"iss": "authorino", // TODO: This needs to be replaced with an HTTP endpoint wherefrom an OpenID Connnect well-known config can be downloaded, including inside a`jwks_uri` claim that points to another HTTP endpoint where a JSON `{ "keys": [{ <w.SigningKey> }] }` can be obtained
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
