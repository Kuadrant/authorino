package evaluators

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/kuadrant/authorino/pkg/json"

	"gotest.tools/assert"
)

func TestEvaluatorCacheLongStringKey(t *testing.T) {
	// given a key built from 40 group names, longer on its own than the 1000 B entry limit of a 1 MB cache
	withEvaluatorCacheSize(t, 1)
	groups := make([]string, 40)
	for i := range groups {
		groups[i] = fmt.Sprintf("system:serviceaccounts:tenant-%02d-premium-subscribers", i)
	}
	longKey := strings.Join(groups, ",")
	assert.Assert(t, len(longKey) > 1000)
	cache := newTestEvaluatorCache(t, longKey)

	// when
	key, err := cache.ResolveKeyFor(`{}`)
	assert.NilError(t, err)
	assert.NilError(t, cache.Set(key, map[string]any{"subscription": "premium"}))

	// then
	cached, err := cache.Get(key)
	assert.NilError(t, err)
	assert.DeepEqual(t, cached, map[string]any{"subscription": "premium"})
}

func TestEvaluatorCacheHashesLongStringKeys(t *testing.T) {
	for name, tc := range map[string]struct{ a, b string }{
		"at digest size": {strings.Repeat("g", sha256.Size), strings.Repeat("g", sha256.Size-1) + "h"},
		"long":           {strings.Repeat("g", 1500), strings.Repeat("g", 1499) + "h"},
		// JSON encoding would turn both into U+FFFD
		"invalid UTF-8": {strings.Repeat("\xff", sha256.Size), strings.Repeat("\xfe", sha256.Size)},
	} {
		t.Run(name, func(t *testing.T) {
			// given
			a := newTestEvaluatorCache(t, tc.a)
			b := newTestEvaluatorCache(t, tc.b)

			// when
			keyA, err := a.ResolveKeyFor(`{}`)
			assert.NilError(t, err)
			keyB, err := b.ResolveKeyFor(`{}`)
			assert.NilError(t, err)

			// then
			assert.Equal(t, len(keyA.(string)), sha256.Size)
			assert.Equal(t, len(keyB.(string)), sha256.Size)
			assert.Assert(t, keyA != keyB)
			assert.Assert(t, !strings.Contains(keyA.(string), tc.a))
		})
	}
}

func TestEvaluatorCacheKeepsShortStringKeys(t *testing.T) {
	for _, key := range []string{"", "/hello", "\xff", strings.Repeat("g", sha256.Size-1)} {
		// given
		cache := newTestEvaluatorCache(t, key)

		// when
		resolved, err := cache.ResolveKeyFor(`{}`)
		assert.NilError(t, err)

		// then
		assert.Equal(t, resolved, key)
	}
}

func TestEvaluatorCacheKeysNeverGrow(t *testing.T) {
	// limit is the largest key plus value that a 1 MB cache stores
	const limit = 1000
	for _, key := range []string{"k", strings.Repeat("k", sha256.Size-1), strings.Repeat("k", sha256.Size), strings.Repeat("k", 1500)} {
		// given a value that fits next to the key, or next to 32 bytes when the key is longer
		cache := newTestEvaluatorCache(t, key)
		resolved, err := cache.ResolveKeyFor(`{}`)
		assert.NilError(t, err)
		valueSize := limit - min(len(key), sha256.Size)

		// when, with a JSON string value 2 bytes longer than the string
		err = cache.Set(resolved, strings.Repeat("x", valueSize-2))

		// then
		assert.NilError(t, err, "key of %d bytes", len(key))
	}
}

func TestEvaluatorCacheKeepsNonStringKeys(t *testing.T) {
	// given
	withEvaluatorCacheSize(t, 1)
	cache := NewEvaluatorCache(&json.JSONValue{Pattern: "auth.identity.groups"}, 60)
	t.Cleanup(func() { _ = cache.Shutdown() })

	// when
	list, err := cache.ResolveKeyFor(`{"auth":{"identity":{"groups":["a","b"]}}}`)
	assert.NilError(t, err)
	missing, err := cache.ResolveKeyFor(`{"auth":{"identity":{}}}`)
	assert.NilError(t, err)

	// then
	assert.DeepEqual(t, list, []any{"a", "b"})
	assert.Assert(t, missing == nil)
}

func TestEvaluatorCacheSetErrorOmitsKey(t *testing.T) {
	for name, secretKey := range map[string]string{
		"short key, stored as it is": "api-key-do-not-log-me",
		"long key, hashed":           "sha256~token-do-not-log-me-0123456789abcdef",
	} {
		t.Run(name, func(t *testing.T) {
			// given an entry too large to store because of its value
			cache := newTestEvaluatorCache(t, secretKey)
			key, err := cache.ResolveKeyFor(`{}`)
			assert.NilError(t, err)

			// when
			err = cache.Set(key, strings.Repeat("x", 1200))

			// then
			assert.ErrorContains(t, err, "value of 1202 bytes")
			assert.Assert(t, !strings.Contains(err.Error(), secretKey), err)
		})
	}
}

func newTestEvaluatorCache(t *testing.T, staticKey string) EvaluatorCache {
	t.Helper()
	withEvaluatorCacheSize(t, 1)
	cache := NewEvaluatorCache(&json.JSONValue{Static: staticKey}, 60)
	t.Cleanup(func() { _ = cache.Shutdown() })
	return cache
}

func withEvaluatorCacheSize(t *testing.T, sizeInMB int) {
	t.Helper()
	previous := EvaluatorCacheSize
	t.Cleanup(func() { EvaluatorCacheSize = previous })
	EvaluatorCacheSize = sizeInMB
}
