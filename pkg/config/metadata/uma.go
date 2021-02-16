package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/3scale-labs/authorino/pkg/config/common"
)

type UMA struct {
	Endpoint     string `yaml:"endpoint,omitempty"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

func (self *UMA) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	// discover uma config
	provider, err := self.NewProvider(ctx)
	if err != nil {
		return nil, err
	}

	// get the protection API token (PAT)
	tokenURL, _ := self.clientAuthenticatedURL(provider.GetTokenURL())
	formData := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL.String(), bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var pat PAT
	err = unmashalJSONResponse(resp, &pat, nil)
	if err != nil {
		return nil, fmt.Errorf("uma: failed to decode PAT: %v", err)
	}

	// query resources by URI
	resourceRegistrationURL, _ := url.Parse(provider.GetResourceRegistrationURL())
	queryResourcesURL := resourceRegistrationURL
	queryResourcesURL.RawQuery = "uri=" + authContext.GetRequest().Attributes.Request.Http.GetPath()
	var resourceIDs []string
	err = getPATAuthenticatedJSON(queryResourcesURL.String(), pat, ctx, &resourceIDs)
	if err != nil {
		return nil, err
	}

	// get each resource data
	resourceData := make([]interface{}, len(resourceIDs))
	for i := range resourceIDs {
		resourceId := resourceIDs[i]
		resourceURL := resourceRegistrationURL
		resourceURL.Path += "/" + resourceId
		var d interface{}
		_ = getPATAuthenticatedJSON(resourceURL.String(), pat, ctx, &d)
		resourceData[i] = d
	}

	return resourceData, nil
}

func (self *UMA) NewProvider(ctx context.Context) (*Provider, error) {
	// discover uma config
	wellKnownURL := strings.TrimSuffix(self.Endpoint, "/") + "/.well-known/uma2-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var p providerJSON
	var rawClaims []byte
	err = unmashalJSONResponse(resp, &p, &rawClaims)
	if err != nil {
		return nil, fmt.Errorf("uma: failed to decode provider discovery object: %v", err)
	}

	// verify same issuer
	if p.Issuer != self.Endpoint {
		return nil, fmt.Errorf("uma: issuer did not match the issuer returned by provider, expected %q got %q", self.Endpoint, p.Issuer)
	}

	return &Provider{
		issuer:                  p.Issuer,
		tokenURL:                p.TokenURL,
		resourceRegistrationURL: p.ResourceRegistrationURL,
		rawClaims:               rawClaims,
	}, nil
}

func (self *UMA) clientAuthenticatedURL(rawurl string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	parsedURL.User = url.UserPassword(self.ClientID, self.ClientSecret)
	return parsedURL, nil
}

func getPATAuthenticatedJSON(rawurl string, pat PAT, ctx context.Context, v interface{}) error {
	// build the request
	req, err := http.NewRequestWithContext(ctx, "GET", rawurl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+pat.String())

	// get the response
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return unmashalJSONResponse(resp, &v, nil)
}

type Provider struct {
	issuer                  string
	tokenURL                string
	resourceRegistrationURL string

	// Raw claims returned by the server.
	rawClaims []byte
}

func (self *Provider) GetTokenURL() string {
	return self.tokenURL
}

func (self *Provider) GetResourceRegistrationURL() string {
	return self.resourceRegistrationURL
}

type providerJSON struct {
	Issuer                  string `json:"issuer"`
	TokenURL                string `json:"token_endpoint"`
	ResourceRegistrationURL string `json:"resource_registration_endpoint"`
}

func unmashalJSONResponse(resp *http.Response, v interface{}, b *[]byte) error {
	// read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if b != nil {
		*b = body
	}

	// check http status ok
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, body)
	}

	// decode as json and return if ok
	err = json.Unmarshal(body, v)
	if err == nil {
		return nil
	}

	// check json response content type
	ct := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

type PAT struct {
	AccessToken string `json:"access_token"`
}

func (self *PAT) String() string {
	return self.AccessToken
}
