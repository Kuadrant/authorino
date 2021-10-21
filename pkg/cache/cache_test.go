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

func (f *BogusIdentity) Call(_ common.AuthPipeline, _ context.Context) (interface{}, error) {
	return true, nil
}

func TestCache(t *testing.T) {
	c := NewCache()

	apiFindIdIdentityConfig := &BogusIdentity{}
	identities := make([]common.AuthConfigEvaluator, 1)
	identities[0] = apiFindIdIdentityConfig
	exampleConfig := config.APIConfig{
		IdentityConfigs:      identities,
		MetadataConfigs:      nil,
		AuthorizationConfigs: nil,
	}

	// Set a key
	if err := c.Set("id", "testing.host", exampleConfig, false); err != nil {
		t.Error(err)
	}

	// Set a second key with same id
	if err := c.Set("id", "testing.host.2", exampleConfig, false); err != nil {
		t.Error(err)
	}

	// Set a third key with different id
	if err := c.Set("id2", "testing.host.3", exampleConfig, false); err != nil {
		t.Error(err)
	}

	// Get keys associated with an id
	keys := c.FindKeys("id")
	sort.Strings(keys)
	assert.DeepEqual(t, keys, []string{"testing.host", "testing.host.2"})

	keys = c.FindKeys("id2")
	sort.Strings(keys)
	assert.DeepEqual(t, keys, []string{"testing.host.3"})

	keys = c.FindKeys("id3")
	sort.Strings(keys)
	assert.Check(t, keys == nil)

	// Get id associated with a host
	id, found := c.FindId("testing.host")
	assert.Check(t, found)
	assert.Equal(t, id, "id")

	id, found = c.FindId("testing.host.2")
	assert.Check(t, found)
	assert.Equal(t, id, "id")

	id, found = c.FindId("testing.host.3")
	assert.Check(t, found)
	assert.Equal(t, id, "id2")

	id, found = c.FindId("testing.host.4")
	assert.Check(t, !found)
	assert.Equal(t, id, "")

	// Set a same host again without override
	err := c.Set("id", "testing.host.2", exampleConfig, false)
	assert.Check(t, err != nil)

	// Get a single key and check that it is what we expect
	config := c.Get("testing.host")
	assert.DeepEqual(t, *config, exampleConfig)

	config = c.Get("testing.host.2")
	assert.DeepEqual(t, *config, exampleConfig)

	config = c.Get("testing.host.4")
	assert.Check(t, config == nil)

	// Delete the id, so both entries should be empty.
	c.Delete("id")

	config = c.Get("testing.host")
	assert.Check(t, config == nil)

	config = c.Get("testing.host.2")
	assert.Check(t, config == nil)

	config = c.Get("testing.host.3")
	assert.DeepEqual(t, *config, exampleConfig)

	c.Delete("id2")

	config = c.Get("testing.host.3")
	assert.Check(t, config == nil)
}
