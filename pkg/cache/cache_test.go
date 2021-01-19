package cache

import (
	"github.com/3scale-labs/authorino/pkg/config"
	"gotest.tools/assert"
	"testing"
)

func TestCache(t *testing.T) {
	c := NewCache()

	exampleConfig := config.APIConfig{
		Enabled:              true,
		IdentityConfigs:      nil,
		MetadataConfigs:      nil,
		AuthorizationConfigs: nil,
	}

	// Set one host.
	err := c.Set("key", "testing.host", exampleConfig, false)
	if err != nil {
		t.Error(err)
	}

	// Set a second host with the same key
	err = c.Set("key", "testing.host.2", exampleConfig, false)
	if err != nil {
		t.Error(err)
	}

	// Set a third host with a different key
	err = c.Set("key2", "testing.host.3", exampleConfig, false)
	if err != nil {
		t.Error(err)
	}

	// Check if we return an error with override to false trying to overwrite an already existing
	// entry.
	err = c.Set("key", "testing.host.2", exampleConfig, false)
	assert.Check(t, err != nil)

	// Check if the list contains all the configs
	configs := c.List()
	assert.Check(t, len(configs) == 3)

	assert.Check(t, configs["testing.host"].Enabled == true)
	assert.Check(t, configs["testing.host.2"].Enabled == true)
	assert.Check(t, configs["testing.host.3"].Enabled == true)

	// Get a single hosts and check that it is what we expect
	config := c.Get("testing.host")
	assert.DeepEqual(t, config, exampleConfig)

	config = c.Get("testing.host.2")
	assert.DeepEqual(t, config, exampleConfig)

	// Delete the key, so both entries should be empty.
	c.Delete("key")

	config = c.Get("testing.host")
	assert.Assert(t, !config.Enabled)

	config = c.Get("testing.host.2")
	assert.Assert(t, !config.Enabled)

	config = c.Get("testing.host.3")
	assert.Assert(t, config.Enabled)

	c.Delete("key2")

	config = c.Get("testing.host.3")
	assert.Assert(t, !config.Enabled)

}
