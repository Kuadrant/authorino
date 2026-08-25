package index

import (
	"context"
	"sort"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators"

	"gotest.tools/assert"
)

// TestAuthConfigTree tests operations to build and modify the following index tree:
//
//	                   ┌───┐
//	         ┌─────────┤ . ├────────┐
//	         │         └───┘        │
//	         │                      │
//	         │                      │
//	      ┌──┴─┐                 ┌──┴──┐
//	  ┌───┤ io ├──┐          ┌───┤ com ├───┐
//	  │   └────┘  │          │   └─────┘   │
//	  │           │          │             │
//	  │           │          │             │
//	┌─┴─┐      ┌──┴──┐    ┌──┴───┐     ┌───┴──┐
//	│ * │      │ nip │    │ pets │   ┌─┤ acme ├─┐
//	└───┘      └──┬──┘    └──┬───┘   │ └──────┘ │
//	  ▲           │          │       │          │
//	  │           │          │       │          │
//	  │    ┌──────┴─────┐  ┌─┴─┐  ┌──┴──┐     ┌─┴─┐
//	auth-1 │ talker-api │  │ * │  │ api │     │ * │
//	       └────────────┘  └───┘  └─────┘     └───┘
//	              ▲          ▲       ▲          ▲
//	              │          │       │          │
//	              │          │       │          │
//	              └──auth-2──┘     auth-3     auth-4
func TestAuthConfigTree(t *testing.T) {
	c := newAuthConfigTree()

	authConfig1 := buildTestAuthConfig()
	authConfig2 := buildTestAuthConfig()
	authConfig3 := buildTestAuthConfig()
	authConfig4 := buildTestAuthConfig()

	// Build the index
	// Set the more generic host first
	if err := c.Set("auth-1", "*.io", authConfig1, false); err != nil {
		t.Error(err)
	}

	// ...and then the more specific one
	if err := c.Set("auth-2", "talker-api.nip.io", authConfig2, false); err != nil {
		t.Error(err)
	}

	if err := c.Set("auth-2", "*.pets.com", authConfig2, false); err != nil {
		t.Error(err)
	}

	// Set the more specific host first
	if err := c.Set("auth-3", "api.acme.com", authConfig3, false); err != nil {
		t.Error(err)
	}

	// ...and then the more generic one
	if err := c.Set("auth-4", "*.acme.com", authConfig4, false); err != nil {
		t.Error(err)
	}

	// Get keys associated with an id
	keys := c.FindKeys("auth-1")
	sort.Strings(keys)
	assert.DeepEqual(t, keys, []string{"*.io"})

	keys = c.FindKeys("auth-2")
	sort.Strings(keys)
	assert.DeepEqual(t, keys, []string{"*.pets.com", "talker-api.nip.io"})

	keys = c.FindKeys("auth-x")
	sort.Strings(keys)
	assert.Check(t, keys == nil)

	// Get id associated with a host
	id, found := c.FindId("*.pets.com")
	assert.Check(t, found)
	assert.Equal(t, id, "auth-2")

	id, found = c.FindId("talker-api.nip.io")
	assert.Check(t, found)
	assert.Equal(t, id, "auth-2")

	id, found = c.FindId("*.acme.com")
	assert.Check(t, found)
	assert.Equal(t, id, "auth-4")

	id, found = c.FindId("undefined.com")
	assert.Check(t, !found)
	assert.Equal(t, id, "")

	// Set a same host again without override
	err := c.Set("auth-5", "talker-api.nip.io", buildTestAuthConfig(), false)
	assert.Check(t, err != nil)

	// Get a single key and check that it is what we expect
	config := c.Get("dogs.pets.com")
	assert.DeepEqual(t, *config, authConfig2)

	config = c.Get("api.acme.com")
	assert.DeepEqual(t, *config, authConfig3)

	config = c.Get("www.acme.com")
	assert.DeepEqual(t, *config, authConfig4)

	config = c.Get("talker-api.nip.io")
	assert.DeepEqual(t, *config, authConfig2)

	config = c.Get("foo.nip.io")
	assert.DeepEqual(t, *config, authConfig1)

	config = c.Get("foo.org")
	assert.Check(t, config == nil)

	// Delete the id, so all associated entries should be deleted
	c.Delete("auth-2")

	config = c.Get("dogs.pets.com")
	assert.Check(t, config == nil)

	config = c.Get("talker-api.nip.io")
	assert.DeepEqual(t, *config, authConfig1) // because `*.io <- auth-1` is still in the tree

	config = c.Get("api.acme.com")
	assert.DeepEqual(t, *config, authConfig3)

	c.Delete("auth-3")

	config = c.Get("api.acme.com")
	assert.DeepEqual(t, *config, authConfig4) // because `*.acme.com <- auth-4` is still in the tree
}

type bogusIdentity struct{}

func (f *bogusIdentity) Call(_ auth.AuthPipeline, _ context.Context) (interface{}, error) {
	return true, nil
}

func buildTestAuthConfig() evaluators.AuthConfig {
	return evaluators.AuthConfig{
		IdentityConfigs:      []auth.AuthConfigEvaluator{&bogusIdentity{}},
		MetadataConfigs:      nil,
		AuthorizationConfigs: nil,
	}
}

func TestDeleteKeyPrunesTheKeysOfTheId(t *testing.T) {
	c := newAuthConfigTree()
	authConfig := buildTestAuthConfig()

	assert.NilError(t, c.Set("auth-1", "talker-api.nip.io", authConfig, false))
	assert.NilError(t, c.Set("auth-1", "echo-api.nip.io", authConfig, false))
	assert.Equal(t, len(c.FindKeys("auth-1")), 2)

	c.DeleteKey("auth-1", "talker-api.nip.io")

	// FindKeys() must not keep reporting a host the resource no longer owns: cleanConfigs()
	// resolves the config to clean from FindKeys()[0] and would otherwise pick up whichever
	// AuthConfig owns that host now
	assert.DeepEqual(t, c.FindKeys("auth-1"), []string{"echo-api.nip.io"})
	assert.Check(t, c.Get("talker-api.nip.io") == nil)
	assert.Check(t, c.Get("echo-api.nip.io") != nil)
}

func TestDeleteRemovesTheIdFromTheKeys(t *testing.T) {
	c := newAuthConfigTree()
	authConfig := buildTestAuthConfig()

	assert.NilError(t, c.Set("auth-1", "talker-api.nip.io", authConfig, false))
	c.Delete("auth-1")

	assert.Equal(t, len(c.FindKeys("auth-1")), 0)
	assert.Check(t, c.Empty())
}

func TestSetDoesNotDuplicateKeys(t *testing.T) {
	c := newAuthConfigTree()
	authConfig := buildTestAuthConfig()

	// every reconcile of an unchanged AuthConfig re-indexes the same hosts
	for i := 0; i < 5; i++ {
		assert.NilError(t, c.Set("auth-1", "talker-api.nip.io", authConfig, true))
	}

	assert.DeepEqual(t, c.FindKeys("auth-1"), []string{"talker-api.nip.io"})
}

func TestDeleteKeyDoesNotStealTheHostOfAnotherId(t *testing.T) {
	c := newAuthConfigTree()
	authConfig := buildTestAuthConfig()

	// auth-1 owns both hosts, then gets narrowed down to one of them
	assert.NilError(t, c.Set("auth-1", "talker-api.nip.io", authConfig, false))
	assert.NilError(t, c.Set("auth-1", "echo-api.nip.io", authConfig, false))
	c.DeleteKey("auth-1", "talker-api.nip.io")

	// auth-2 legitimately takes over the released host (addToIndex() always sets with override)
	assert.NilError(t, c.Set("auth-2", "talker-api.nip.io", authConfig, true))

	id, found := c.FindId("talker-api.nip.io")
	assert.Check(t, found)
	assert.Equal(t, id, "auth-2")
	assert.DeepEqual(t, c.FindKeys("auth-1"), []string{"echo-api.nip.io"})
}
