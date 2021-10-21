package metadata

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
)

type providerJSON struct {
	Issuer                  string `json:"issuer"`
	TokenURL                string `json:"token_endpoint"`
	ResourceRegistrationURL string `json:"resource_registration_endpoint"`
}

type Provider struct {
	issuer                  string
	tokenURL                string
	resourceRegistrationURL string

	// Raw claims returned by the server.
	rawClaims []byte
}

func (provider *Provider) GetTokenURL() string {
	return provider.tokenURL
}

func (provider *Provider) GetResourcesByURI(uri string, pat PAT, ctx context.Context) ([]interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	resourceIDs, err := provider.queryResourcesByURI(uri, pat, ctx)
	if err != nil {
		return nil, err
	}
	return provider.getResourcesByIDs(resourceIDs, pat, ctx)
}

func (provider *Provider) queryResourcesByURI(uri string, pat PAT, ctx context.Context) ([]string, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	queryResourcesURL, _ := url.Parse(provider.resourceRegistrationURL)
	queryResourcesURL.RawQuery = "uri=" + uri

	log.FromContext(ctx).V(1).Info("querying resources by uri", "url", queryResourcesURL.String())

	var resourceIDs []string
	if err := pat.Get(queryResourcesURL.String(), ctx, &resourceIDs); err != nil {
		return nil, err
	} else {
		return resourceIDs, nil
	}
}

func (provider *Provider) getResourcesByIDs(resourceIDs []string, pat PAT, ctx context.Context) ([]interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	waitGroup := new(sync.WaitGroup)
	size := len(resourceIDs)
	buf := make(chan interface{}, size)

	waitGroup.Add(size)
	for _, resourceID := range resourceIDs {
		go func(id string) {
			defer waitGroup.Done()

			if data, err := provider.getResourceByID(id, pat, ctx); err == nil {
				buf <- data
			}
		}(resourceID)
	}

	waitGroup.Wait()
	close(buf)

	resourceData := make([]interface{}, 0)
	for resource := range buf {
		resourceData = append(resourceData, resource)
	}
	return resourceData, nil
}

func (provider *Provider) getResourceByID(resourceID string, pat PAT, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	resourceURL, _ := url.Parse(provider.resourceRegistrationURL)
	resourceURL.Path += "/" + resourceID

	log.FromContext(ctx).V(1).Info("getting resource data", "url", resourceURL.String())

	var data interface{}
	if err := pat.Get(resourceURL.String(), ctx, &data); err != nil {
		return nil, err
	}
	return data, nil
}

type PAT struct {
	AccessToken string `json:"access_token"`
}

func (pat *PAT) String() string {
	return pat.AccessToken
}

func (pat *PAT) Get(rawurl string, ctx context.Context, v interface{}) error {
	if err := common.CheckContext(ctx); err != nil {
		return err
	}

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

	return common.UnmashalJSONResponse(resp, &v, nil)
}

func NewUMAMetadata(endpoint string, clientID string, clientSecret string) (*UMA, error) {
	uma := &UMA{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	if err := uma.discover(); err != nil {
		return nil, err
	} else {
		return uma, nil
	}
}

type UMA struct {
	Endpoint     string `yaml:"endpoint,omitempty"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`

	provider *Provider
}

func (uma *UMA) wellKnownConfigEndpoint() string {
	return strings.TrimSuffix(uma.Endpoint, "/") + "/.well-known/uma2-configuration"
}

func (uma *UMA) discover() error {
	if resp, err := http.Get(uma.wellKnownConfigEndpoint()); err != nil {
		return fmt.Errorf("failed to fetch uma config: %v", err)
	} else {
		defer resp.Body.Close()

		var p providerJSON
		var rawClaims []byte
		if err = common.UnmashalJSONResponse(resp, &p, &rawClaims); err != nil {
			return fmt.Errorf("failed to decode uma provider discovery object: %v", err)
		}

		// verify same issuer
		if p.Issuer != uma.Endpoint {
			return fmt.Errorf("uma endpoint does not match the issuer returned by provider, expected %q got %q", uma.Endpoint, p.Issuer)
		}

		uma.provider = &Provider{
			issuer:                  p.Issuer,
			tokenURL:                p.TokenURL,
			resourceRegistrationURL: p.ResourceRegistrationURL,
			rawClaims:               rawClaims,
		}

		return nil
	}
}

func (uma *UMA) Call(pipeline common.AuthPipeline, parentCtx context.Context) (interface{}, error) {
	ctx := log.IntoContext(parentCtx, log.FromContext(parentCtx).WithName("uma"))

	// get the protection API token (PAT)
	var pat PAT
	if err := uma.requestPAT(ctx, &pat); err != nil {
		return nil, err
	}

	// get resource data
	uri := pipeline.GetHttp().GetPath()
	resourceData, err := uma.provider.GetResourcesByURI(uri, pat, ctx)

	if err != nil {
		return nil, err
	}

	return resourceData, nil
}

func (uma *UMA) clientAuthenticatedURL(rawurl string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	parsedURL.User = url.UserPassword(uma.ClientID, uma.ClientSecret)
	return parsedURL, nil
}

func (uma *UMA) requestPAT(ctx context.Context, pat *PAT) error {
	if err := common.CheckContext(ctx); err != nil {
		return err
	}

	// build the request
	tokenURL, _ := uma.clientAuthenticatedURL(uma.provider.GetTokenURL())
	data := url.Values{"grant_type": {"client_credentials"}}
	encodedData := bytes.NewBufferString(data.Encode())
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL.String(), encodedData)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	log.FromContext(ctx).V(1).Info("requesting pat", "url", tokenURL.String(), "data", encodedData, "headers", req.Header)

	// get the response
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	// parse the pat
	if err := common.UnmashalJSONResponse(resp, pat, nil); err != nil {
		return fmt.Errorf("failed to decode uma pat: %v", err)
	}

	return nil
}
