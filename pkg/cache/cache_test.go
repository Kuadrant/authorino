package cache

import (
	"context"
	"sort"
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

	// Get hosts associated with a key
	hosts := c.Hosts("key")
	sort.Strings(hosts)
	assert.DeepEqual(t, hosts, []string{"testing.host", "testing.host.2"})

	hosts = c.Hosts("key2")
	sort.Strings(hosts)
	assert.DeepEqual(t, hosts, []string{"testing.host.3"})

	hosts = c.Hosts("key3")
	sort.Strings(hosts)
	assert.Check(t, hosts == nil)

	// Get key associated with a host
	key := c.Key("testing.host")
	assert.Equal(t, *key, "key")

	key = c.Key("testing.host.2")
	assert.Equal(t, *key, "key")

	key = c.Key("testing.host.3")
	assert.Equal(t, *key, "key2")

	key = c.Key("testing.host.4")
	assert.Check(t, key == nil)

	// Set a same host again without override
	err := c.Set("key", "testing.host.2", exampleConfig, false)
	assert.Check(t, err != nil)

	// Get a single hosts and check that it is what we expect
	config := c.Get("testing.host")
	assert.DeepEqual(t, *config, exampleConfig)

	config = c.Get("testing.host.2")
	assert.DeepEqual(t, *config, exampleConfig)

	config = c.Get("testing.host.4")
	assert.Check(t, config == nil)

	// Delete the key, so both entries should be empty.
	c.Delete("key")

	config = c.Get("testing.host")
	assert.Check(t, config == nil)

	config = c.Get("testing.host.2")
	assert.Check(t, config == nil)

	config = c.Get("testing.host.3")
	assert.DeepEqual(t, *config, exampleConfig)

	c.Delete("key2")

	config = c.Get("testing.host.3")
	assert.Check(t, config == nil)
}
