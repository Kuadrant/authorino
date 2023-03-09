package metadata

import (
	"bytes"
	gocontext "context"
	gojson "encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/oauth2"

	"go.opentelemetry.io/otel"
	otel_propagation "go.opentelemetry.io/otel/propagation"
)

type GenericHttp struct {
	Endpoint              string
	Method                string
	Body                  *json.JSONValue
	Parameters            []json.JSONProperty
	Headers               []json.JSONProperty
	ContentType           string
	SharedSecret          string
	OAuth2                *oauth2.ClientCredentials
	OAuth2TokenForceFetch bool
	auth.AuthCredentials
}

func (h *GenericHttp) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	if err := context.CheckContext(ctx); err != nil {
		return nil, err
	}

	authJSON := pipeline.GetAuthorizationJSON()
	endpoint := json.ReplaceJSONPlaceholders(h.Endpoint, authJSON)

	req, err := h.buildRequest(ctx, endpoint, authJSON)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse the response as json
	if strings.Contains(strings.Join(resp.Header["Content-Type"], ";"), "application/json") {
		decoder := gojson.NewDecoder(resp.Body)

		var elements []map[string]interface{}

		for {
			var claims map[string]interface{}
			if err = decoder.Decode(&claims); err != nil {
				return nil, err
			}
			elements = append(elements, claims)
			if !decoder.More() {
				break
			}
		}

		if len(elements) > 1 {
			return elements, nil
		} else if len(elements) == 1 {
			return elements[0], nil
		} else {
			return nil, nil
		}
	}

	// parse the response as text
	defer resp.Body.Close()
	str, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return string(str), nil
}

func (h *GenericHttp) buildRequest(ctx gocontext.Context, endpoint, authJSON string) (*http.Request, error) {
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
		requestBody, err = h.buildRequestBody(authJSON)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported method")
	}

	var req *http.Request
	var err error
	if h.AuthCredentials != nil {
		creds := h.SharedSecret
		if h.OAuth2 != nil {
			token, err := h.OAuth2.ClientCredentialsToken(ctx, h.OAuth2TokenForceFetch)
			if err != nil {
				return nil, err
			}
			creds = token.AccessToken
		}
		req, err = h.BuildRequestWithCredentials(ctx, endpoint, method, creds, requestBody)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	}
	if err != nil {
		return nil, err
	}

	for _, header := range h.Headers {
		req.Header.Set(header.Name, fmt.Sprintf("%s", header.Value.ResolveFor(authJSON)))
	}

	req.Header.Set("Content-Type", contentType)
	otel.GetTextMapPropagator().Inject(ctx, otel_propagation.HeaderCarrier(req.Header))

	if logger := log.FromContext(ctx).WithName("http").V(1); logger.Enabled() {
		logData := []interface{}{
			"method", method,
			"url", endpoint,
			"headers", req.Header,
		}
		if requestBody != nil {
			if b, ok := requestBody.(*bytes.Buffer); ok {
				logData = append(logData, "body", b.String())
			}
		}
		logger.Info("sending request", logData...)
	}

	return req, nil
}

func (h *GenericHttp) buildRequestBody(authData string) (io.Reader, error) {
	if h.Body != nil {
		if body, err := json.StringifyJSON(h.Body.ResolveFor(authData)); err != nil {
			return nil, fmt.Errorf("failed to encode http request")
		} else {
			return bytes.NewBufferString(body), nil
		}
	}

	data := make(map[string]interface{})
	for _, param := range h.Parameters {
		data[param.Name] = param.Value.ResolveFor(authData)
	}

	switch h.ContentType {
	case "application/x-www-form-urlencoded":
		formData := url.Values{}
		for key, value := range data {
			if valueAsStr, err := json.StringifyJSON(value); err != nil {
				return nil, fmt.Errorf("failed to encode http request")
			} else {
				formData.Set(key, valueAsStr)
			}
		}
		return bytes.NewBufferString(formData.Encode()), nil

	case "application/json":
		if dataJSON, err := gojson.Marshal(data); err != nil {
			return nil, err
		} else {
			return bytes.NewBuffer(dataJSON), nil
		}

	default:
		return nil, fmt.Errorf("unsupported content-type")
	}
}
