package cache

import (
	"context"
	"testing"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/config"
	"gotest.tools/assert"
)

type BogusIdentity struct{}

func (f *BogusIdentity) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	return true, nil
}

func TestCache(t *testing.T) {
	c := NewCache()

	apiKeyIdentityConfig := &BogusIdentity{}
	identities := make([]common.AuthConfigEvaluator, 1)
	identities[0] = apiKeyIdentityConfig
	exampleConfig := config.APIConfig{
		IdentityConfigs:      identities,
		MetadataConfigs:      nil,
		AuthorizationConfigs: nil,
	}

	emptyConfig := config.APIConfig{
		IdentityConfigs:      nil,
		MetadataConfigs:      nil,
		AuthorizationConfigs: nil,
	}

	// Set a host
	if err := c.Set("key", "testing.host", exampleConfig, false); err != nil {
		t.Error(err)
	}

	// Set a second host with same key
	if err := c.Set("key", "testing.host.2", exampleConfig, false); err != nil {
		t.Error(err)
	}

	// Set a third host with different key
	if err := c.Set("key2", "testing.host.3", exampleConfig, false); err != nil {
		t.Error(err)
	}

	// Set a same host again without override
	err := c.Set("key", "testing.host.2", exampleConfig, false)
	assert.Check(t, err != nil)

	// Check if the list contains all the configs
	configs := c.List()
	assert.Check(t, len(configs) == 3)

	assert.DeepEqual(t, exampleConfig, configs["testing.host"])
	assert.DeepEqual(t, exampleConfig, configs["testing.host.2"])
	assert.DeepEqual(t, exampleConfig, configs["testing.host.3"])

	// Get a single hosts and check that it is what we expect
	config := c.Get("testing.host")
	assert.DeepEqual(t, config, exampleConfig)

	config = c.Get("testing.host.2")
	assert.DeepEqual(t, config, exampleConfig)

	// Delete the key, so both entries should be empty.
	c.Delete("key")

	config = c.Get("testing.host")
	assert.DeepEqual(t, emptyConfig, config)

	config = c.Get("testing.host.2")
	assert.DeepEqual(t, emptyConfig, config)

	config = c.Get("testing.host.3")
	assert.DeepEqual(t, exampleConfig, config)

	c.Delete("key2")

	config = c.Get("testing.host.3")
	assert.DeepEqual(t, emptyConfig, config)
}
