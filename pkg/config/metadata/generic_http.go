package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"
)

type GenericHttp struct {
	Endpoint     string
	Method       string
	Parameters   []common.JSONProperty
	ContentType  string
	SharedSecret string
	auth_credentials.AuthCredentials
}

func (h *GenericHttp) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	authData, _ := json.Marshal(pipeline.GetDataForAuthorization())
	endpoint := common.ReplaceJSONPlaceholders(h.Endpoint, string(authData))

	var requestBody io.Reader
	var contentType string

	method := h.Method
	switch method {
	case "GET":
		contentType = "text/plain"
		requestBody = nil
	case "POST":
		var err error
		contentType = h.ContentType
		requestBody, err = h.buildRequestBody(string(authData))
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported method")
	}

	req, err := h.BuildRequestWithCredentials(ctx, endpoint, method, h.SharedSecret, requestBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)

	if logger := log.FromContext(ctx).WithName("http").V(1); logger.Enabled() {
		logData := []interface{}{
			"method", method,
			"url", endpoint,
			"headers", req.Header,
		}
		if requestBody != nil {
			var b []byte
			_, _ = requestBody.Read(b)
			logData = append(logData, "body", string(b))
		}
		logger.Info("sending request", logData...)
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

func (h *GenericHttp) buildRequestBody(authData string) (io.Reader, error) {
	data := make(map[string]interface{})
	for _, param := range h.Parameters {
		data[param.Name] = param.Value.ResolveFor(authData)
	}

	switch h.ContentType {
	case "application/x-www-form-urlencoded":
		formData := url.Values{}
		for key, value := range data {
			if valueAsStr, err := common.StringifyJSON(value); err != nil {
				return nil, fmt.Errorf("failed to encode http request")
			} else {
				formData.Set(key, valueAsStr)
			}
		}
		return bytes.NewBufferString(formData.Encode()), nil

	case "application/json":
		if dataJSON, err := json.Marshal(data); err != nil {
			return nil, err
		} else {
			return bytes.NewBuffer(dataJSON), nil
		}

	default:
		return nil, fmt.Errorf("unsupported content-type")
	}
}
