package cache

import (
	"context"
	"sort"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators"

	"gotest.tools/assert"
)

// TestAuthConfigTree tests operations to build and modify the following cache tree:
//                    ┌───┐
//          ┌─────────┤ . ├──────────┐
//          │         └───┘          │
//          │                        │
//          │                        │
//       ┌──┴─┐                   ┌──┴──┐
//   ┌───┤ io ├───┐           ┌───┤ com ├───┐
//   │   └────┘   │           │   └─────┘   │
//   │            │           │             │
//   │            │           │             │
//   │            │           │             │
// ┌─┴─┐       ┌──┴──┐    ┌───┴──┐      ┌───┴──┐
// │ * │       │ nip │    │ pets │    ┌─┤ acme ├─┐
// └───┘       └──┬──┘    └───┬──┘    │ └──────┘ │
//   ▲            │           │       │          │
//   │            │           │       │          │
//   │            │           │       │          │
//   │      ┌─────┴──────┐  ┌─┴─┐  ┌──┴──┐     ┌─┴─┐
// auth-1   │ talker-api │  │ * │  │ api │     │ * │
//          └────────────┘  └───┘  └─────┘     └───┘
//                ▲           ▲       ▲          ▲
//                │           │       │          │
//                │           │       │          │
//                └───auth-2──┘     auth-3     auth-4
func TestAuthConfigTree(t *testing.T) {
	c := newAuthConfigTree()

	authConfig1 := buildTestAuthConfig()
	authConfig2 := buildTestAuthConfig()
	authConfig3 := buildTestAuthConfig()
	authConfig4 := buildTestAuthConfig()

	// Build the cache
	if err := c.Set("auth-1", "*.io", authConfig1, false); err != nil {
		t.Error(err)
	}

	if err := c.Set("auth-2", "*.pets.com", authConfig2, false); err != nil {
		t.Error(err)
	}

	if err := c.Set("auth-2", "talker-api.nip.io", authConfig2, false); err != nil {
		t.Error(err)
	}

	if err := c.Set("auth-3", "api.acme.com", authConfig3, false); err != nil {
		t.Error(err)
	}

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
	assert.DeepEqual(t, *config, authConfig1) // because `*.io -> auth-1` is still in the tree

	config = c.Get("api.acme.com")
	assert.DeepEqual(t, *config, authConfig3)

	c.Delete("auth-3")

	config = c.Get("api.acme.com")
	assert.DeepEqual(t, *config, authConfig4) // because `*.acme.com -> auth-4` is still in the tree
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
