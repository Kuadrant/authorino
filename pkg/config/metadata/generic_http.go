package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
)

type GenericHttp struct {
	Endpoint     string
	Method       string
	SharedSecret string
	auth_credentials.AuthCredentials
}

func (h *GenericHttp) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	var requestBody io.Reader

	method := h.Method
	switch method {
	case "GET":
		requestBody = nil
	case "POST":
		_, identityObject := pipeline.GetResolvedIdentity()
		if reqBody, err := json.Marshal(identityObject); err != nil {
			return nil, err
		} else {
			requestBody = bytes.NewBuffer(reqBody)
		}
	default:
		return nil, fmt.Errorf("unsupported method")
	}

	authData, _ := json.Marshal(pipeline.GetDataForAuthorization())
	endpoint := common.ReplaceJSONPlaceholders(h.Endpoint, string(authData))

	req, err := h.BuildRequestWithCredentials(ctx, endpoint, method, h.SharedSecret, requestBody)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse the response
	var claims map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
