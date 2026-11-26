package evaluators

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/expressions/cel"
	"github.com/kuadrant/authorino/pkg/json"

	"gotest.tools/assert"
)

func TestEvaluatorCacheLongKey(t *testing.T) {
	// given a key built from 40 group names, longer on its own than the 1000 B entry limit of a 1 MB cache
	groups := make([]string, 40)
	for i := range groups {
		groups[i] = fmt.Sprintf("system:serviceaccounts:tenant-%02d-premium-subscribers", i)
	}
	longKey := strings.Join(groups, ",")
	value := map[string]any{"subscription": "premium"}

	t.Run("default cache size", func(t *testing.T) {
		cache := newTestEvaluatorCache(t, &json.JSONValue{Static: longKey}, 1)
		key, err := cache.ResolveKeyFor(`{}`)
		assert.NilError(t, err)

		// when
		err = cache.Set(key, value)

		// then
		assert.ErrorContains(t, err, fmt.Sprintf("cache entry of %d bytes not stored, larger than the limit of 1000 bytes", len(longKey)+2+len(`{"subscription":"premium"}`)))
		cached, err := cache.Get(key)
		assert.NilError(t, err)
		assert.Assert(t, cached == nil, cached)
	})

	t.Run("larger cache", func(t *testing.T) {
		cache := newTestEvaluatorCache(t, &json.JSONValue{Static: longKey}, 4)
		key, err := cache.ResolveKeyFor(`{}`)
		assert.NilError(t, err)

		// when
		assert.NilError(t, cache.Set(key, value))

		// then
		cached, err := cache.Get(key)
		assert.NilError(t, err)
		assert.DeepEqual(t, cached, value)
	})
}

func TestEvaluatorCacheSkipsUnresolvedKey(t *testing.T) {
	// given a template whose placeholder selects nothing
	cache := newTestEvaluatorCache(t, &json.JSONValue{Pattern: "user-{auth.identity.email}"}, 1)

	// when
	key, err := cache.ResolveKeyFor(`{"auth":{"identity":{"sub":"alice"}}}`)

	// then the evaluators run without the cache
	assert.Assert(t, key == nil)
	assert.Assert(t, errors.Is(err, errCacheKeyNotFound), err)
}

func TestEvaluatorCacheKeepsKeysApart(t *testing.T) {
	for name, tc := range map[string]struct {
		keyTemplate     expressions.Value
		authJSON, other string
	}{
		// printed alike by fmt: [bob x y]
		"CEL list": {
			celKeyTemplate(t, `[auth.identity.sub, auth.identity.org]`),
			`{"auth":{"identity":{"sub":"bob x","org":"y"}}}`,
			`{"auth":{"identity":{"sub":"bob","org":"x y"}}}`,
		},
		// rendered alike: acme-eu-bob
		"template": {
			&json.JSONValue{Pattern: "{auth.identity.org}-{auth.identity.sub}"},
			`{"auth":{"identity":{"org":"acme-eu","sub":"bob"}}}`,
			`{"auth":{"identity":{"org":"acme","sub":"eu-bob"}}}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			// given
			cache := newTestEvaluatorCache(t, tc.keyTemplate, 1)
			key, err := cache.ResolveKeyFor(tc.authJSON)
			assert.NilError(t, err)
			otherKey, err := cache.ResolveKeyFor(tc.other)
			assert.NilError(t, err)

			// when
			assert.NilError(t, cache.Set(key, "cached for the first"))

			// then
			cached, err := cache.Get(otherKey)
			assert.NilError(t, err)
			assert.Assert(t, cached == nil, cached)
		})
	}
}

func TestEvaluatorCacheSetErrorOmitsKey(t *testing.T) {
	for name, tc := range map[string]struct {
		secretKey string
		value     any
		sizeMB    int
		wantErr   string
	}{
		"entry too large": {
			"api-key-do-not-log-me", strings.Repeat("x", 1200), 1,
			fmt.Sprintf("cache entry of %d bytes not stored, larger than the limit of 1000 bytes", len(`"api-key-do-not-log-me"`)+1202),
		},
		// a cache this large takes an entry whose key is over freecache's key limit
		"key too large": {
			"do-not-log-me-" + strings.Repeat("k", 66000), "v", 72,
			"cache entry not stored, its key of 66016 bytes is larger than 65535 bytes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			// given
			cache := newTestEvaluatorCache(t, &json.JSONValue{Static: tc.secretKey}, tc.sizeMB)
			key, err := cache.ResolveKeyFor(`{}`)
			assert.NilError(t, err)

			// when
			err = cache.Set(key, tc.value)

			// then
			assert.ErrorContains(t, err, tc.wantErr)
			assert.Assert(t, !strings.Contains(err.Error(), "do-not-log-me"), err)
		})
	}
}

func TestEvaluatorCacheResolveKeyFor(t *testing.T) {
	const authJSON = `{"auth":{"identity":{"sub":"alice","org":null,"nickname":"","groups":["a","b"]}}}`

	for name, tc := range map[string]struct {
		keyTemplate expressions.Value
		wantKey     string
	}{
		"path":                         {&json.JSONValue{Pattern: "auth.identity.sub"}, `"alice"`},
		"path to null":                 {&json.JSONValue{Pattern: "auth.identity.org"}, `null`},
		"path to an empty string":      {&json.JSONValue{Pattern: "auth.identity.nickname"}, `""`},
		"path to a list":               {&json.JSONValue{Pattern: "auth.identity.groups"}, `["a","b"]`},
		"static value":                 {&json.JSONValue{Static: "x"}, `"x"`},
		"template":                     {&json.JSONValue{Pattern: "user-{auth.identity.sub}"}, `["alice"]`},
		"template, empty placeholder":  {&json.JSONValue{Pattern: "{auth.identity.sub}-{auth.identity.nickname}"}, `["alice",""]`},
		"template, null placeholder":   {&json.JSONValue{Pattern: "user-{auth.identity.org}"}, `[null]`},
		"CEL list":                     {celKeyTemplate(t, `[auth.identity.sub, "x"]`), `["alice","x"]`},
		"CEL null":                     {celKeyTemplate(t, `auth.identity.org`), `null`},
		"CEL empty string":             {celKeyTemplate(t, `auth.identity.nickname`), `""`},
		"CEL string that reads a list": {celKeyTemplate(t, `'["alice","x"]'`), `"[\"alice\",\"x\"]"`},
	} {
		t.Run(name, func(t *testing.T) {
			cache := newTestEvaluatorCache(t, tc.keyTemplate, 1)
			key, err := cache.ResolveKeyFor(authJSON)
			assert.NilError(t, err)
			assert.Equal(t, key, tc.wantKey)
		})
	}

	for name, keyTemplate := range map[string]expressions.Value{
		"missing path":                &json.JSONValue{Pattern: "auth.identity.email"},
		"empty static value":          &json.JSONValue{},
		"template, missing":           &json.JSONValue{Pattern: "user-{auth.identity.email}"},
		"template, one of two":        &json.JSONValue{Pattern: "{auth.identity.sub}-{auth.identity.email}"},
		"template, no path in braces": &json.JSONValue{Pattern: "user-{}"},
		"template, unterminated":      &json.JSONValue{Pattern: "user-{auth.identity.sub"},
	} {
		t.Run(name, func(t *testing.T) {
			cache := newTestEvaluatorCache(t, keyTemplate, 1)
			key, err := cache.ResolveKeyFor(authJSON)
			assert.Assert(t, key == nil)
			assert.Assert(t, errors.Is(err, errCacheKeyNotFound), err)
		})
	}

	t.Run("CEL runtime error", func(t *testing.T) {
		cache := newTestEvaluatorCache(t, celKeyTemplate(t, `{"k": "v"}[auth.identity.sub]`), 1)
		key, err := cache.ResolveKeyFor(authJSON)
		assert.Assert(t, key == nil)
		assert.ErrorContains(t, err, "no such key")
	})
}

func TestCacheKeyKeepsKeysApart(t *testing.T) {
	for name, tc := range map[string]struct{ a, b any }{
		"string and number":           {"1", float64(1)},
		"null and string":             {nil, "null"},
		"empty string and empty list": {"", []any{}},
		// same text when printed with fmt: [bob x y]
		"lists printed alike": {[]any{"bob x", "y"}, []any{"bob", "x y"}},
		// same text when printed with fmt: map[name:x role:admin sub:alice]
		"objects printed alike":              {map[string]any{"name": "x", "role": "admin", "sub": "alice"}, map[string]any{"name": "x role:admin sub:alice"}},
		"string and list with the same JSON": {`["g"]`, []any{"g"}},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := cacheKey(tc.a)
			assert.NilError(t, err)
			b, err := cacheKey(tc.b)
			assert.NilError(t, err)
			assert.Assert(t, a != b, a)
		})
	}
}

func TestCacheKeyRejectsInvalidUTF8(t *testing.T) {
	// JSON encoding would turn \xff and \xfe alike into U+FFFD
	for name, key := range map[string]any{
		"string":        "\xff",
		"list item":     []any{"\xff"},
		"object member": map[string]any{"\xff": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cacheKey(key)
			assert.Assert(t, errors.Is(err, errInvalidUTF8CacheKey), err)
		})
	}
}

// newTestEvaluatorCache returns an evaluator cache of sizeMB megabytes; the default size is 1 MB.
func newTestEvaluatorCache(t *testing.T, keyTemplate expressions.Value, sizeMB int) EvaluatorCache {
	t.Helper()
	previous := EvaluatorCacheSize
	t.Cleanup(func() { EvaluatorCacheSize = previous })
	EvaluatorCacheSize = sizeMB
	cache := NewEvaluatorCache(keyTemplate, 60)
	t.Cleanup(func() { _ = cache.Shutdown() })
	return cache
}

func celKeyTemplate(t *testing.T, source string) expressions.Value {
	t.Helper()
	expression, err := cel.NewExpression(source)
	assert.NilError(t, err)
	return expression
}
