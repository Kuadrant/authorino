package evaluators

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/expressions/cel"
	"github.com/kuadrant/authorino/pkg/json"

	"gotest.tools/assert"
)

func TestEvaluatorCacheLongStringKey(t *testing.T) {
	// given a key built from 40 group names, longer on its own than the 1000 B entry limit of a 1 MB cache
	groups := make([]string, 40)
	for i := range groups {
		groups[i] = fmt.Sprintf("system:serviceaccounts:tenant-%02d-premium-subscribers", i)
	}
	longKey := strings.Join(groups, ",")
	assert.Assert(t, len(longKey) > 1000)
	cache := newTestEvaluatorCache(t, &json.JSONValue{Static: longKey})

	// when
	key, err := cache.ResolveKeyFor(`{}`)
	assert.NilError(t, err)
	assert.NilError(t, cache.Set(key, map[string]any{"subscription": "premium"}))

	// then
	cached, err := cache.Get(key)
	assert.NilError(t, err)
	assert.DeepEqual(t, cached, map[string]any{"subscription": "premium"})
}

func TestEvaluatorCacheSkipsUnresolvedKey(t *testing.T) {
	// given a template whose placeholder selects nothing
	cache := newTestEvaluatorCache(t, &json.JSONValue{Pattern: "user-{auth.identity.email}"})

	// when
	key, _ := cache.ResolveKeyFor(`{"auth":{"identity":{"sub":"alice"}}}`)

	// then the evaluators run without the cache
	assert.Assert(t, key == nil)
}

func TestEvaluatorCacheKeepsKeysPrintedAlikeApart(t *testing.T) {
	// given two identities whose key lists are printed alike by fmt: [bob x y]
	cache := newTestEvaluatorCache(t, celKeyTemplate(t, `[auth.identity.sub, auth.identity.org]`))
	bob, err := cache.ResolveKeyFor(`{"auth":{"identity":{"sub":"bob x","org":"y"}}}`)
	assert.NilError(t, err)
	other, err := cache.ResolveKeyFor(`{"auth":{"identity":{"sub":"bob","org":"x y"}}}`)
	assert.NilError(t, err)

	// when
	assert.NilError(t, cache.Set(bob, "for bob x"))

	// then
	cached, err := cache.Get(other)
	assert.NilError(t, err)
	assert.Assert(t, cached == nil, cached)
}

func TestEvaluatorCacheSetErrorOmitsKey(t *testing.T) {
	for name, secretKey := range map[string]string{
		"short key, stored as it is": "api-key-do-not-log-me",
		"long key, hashed":           "sha256~token-do-not-log-me-0123456789abcdef",
	} {
		t.Run(name, func(t *testing.T) {
			// given an entry too large to store because of its value
			cache := newTestEvaluatorCache(t, &json.JSONValue{Static: secretKey})
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

func TestCacheKeyHashesLongStrings(t *testing.T) {
	for name, tc := range map[string]struct{ a, b string }{
		"at digest size": {strings.Repeat("g", sha256.Size), strings.Repeat("g", sha256.Size-1) + "h"},
		"long":           {strings.Repeat("g", 1500), strings.Repeat("g", 1499) + "h"},
		// JSON encoding would turn both into U+FFFD
		"invalid UTF-8": {strings.Repeat("\xff", sha256.Size), strings.Repeat("\xfe", sha256.Size)},
	} {
		t.Run(name, func(t *testing.T) {
			// when
			a, err := cacheKey(tc.a)
			assert.NilError(t, err)
			b, err := cacheKey(tc.b)
			assert.NilError(t, err)

			// then
			assert.Equal(t, len(a), sha256.Size)
			assert.Equal(t, len(b), sha256.Size)
			assert.Assert(t, a != b)
			assert.Assert(t, !strings.Contains(a, tc.a))
		})
	}
}

func TestCacheKeyKeepsShortStrings(t *testing.T) {
	for _, key := range []string{"/hello", "\xff", strings.Repeat("g", sha256.Size-1)} {
		encoded, err := cacheKey(key)
		assert.NilError(t, err)
		assert.Equal(t, encoded, key)
	}
}

func TestCacheKeyNeverGrows(t *testing.T) {
	// string keys are never longer than they were
	for _, key := range []string{"k", strings.Repeat("k", sha256.Size-1), strings.Repeat("k", sha256.Size), strings.Repeat("k", 1500)} {
		encoded, err := cacheKey(key)
		assert.NilError(t, err)
		assert.Assert(t, len(encoded) <= min(len(key), sha256.Size), "key of %d bytes", len(key))
	}
	// other keys take sha256.Size bytes, as many as the hex MD5 that gocache stored for them
	for _, key := range []any{float64(1), true, []any{"a"}, map[string]any{"sub": strings.Repeat("a", 1500)}} {
		encoded, err := cacheKey(key)
		assert.NilError(t, err)
		assert.Equal(t, len(encoded), sha256.Size, key)
	}
}

func TestCacheKeyKeepsKeysApart(t *testing.T) {
	object, err := cacheKey(map[string]any{"sub": "alice"})
	assert.NilError(t, err)

	for name, tc := range map[string]struct{ a, b any }{
		"string and number": {"1", float64(1)},
		// same text when printed with fmt: [bob x y]
		"lists printed alike": {[]any{"bob x", "y"}, []any{"bob", "x y"}},
		// same text when printed with fmt: map[name:x role:admin sub:alice]
		"objects printed alike": {map[string]any{"name": "x", "role": "admin", "sub": "alice"}, map[string]any{"name": "x role:admin sub:alice"}},
		// the string has the bytes of the JSON encoding of the list, and is long enough to be hashed
		"string and list with the same JSON":  {`["` + strings.Repeat("g", sha256.Size) + `"]`, []any{strings.Repeat("g", sha256.Size)}},
		"string that reads like a digest":     {object, map[string]any{"sub": "alice"}},
		"string that reads like a cut digest": {object[:sha256.Size-1], map[string]any{"sub": "alice"}},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := cacheKey(tc.a)
			assert.NilError(t, err)
			b, err := cacheKey(tc.b)
			assert.NilError(t, err)
			assert.Assert(t, a != b)
		})
	}
}

func TestCacheKeyRejectsUnusableKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		key  any
		want error
	}{
		"null":         {nil, errNullCacheKey},
		"empty string": {"", errEmptyCacheKey},
		"empty list":   {[]any{}, errEmptyCacheKey},
		"empty object": {map[string]any{}, errEmptyCacheKey},
		// JSON encoding would turn these into U+FFFD
		"invalid UTF-8 in a list":        {[]any{"\xff"}, errInvalidUTF8CacheKey},
		"invalid UTF-8 in an object key": {map[string]any{"\xff": "x"}, errInvalidUTF8CacheKey},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cacheKey(tc.key)
			assert.Assert(t, errors.Is(err, tc.want), err)
		})
	}
}

func TestResolveCacheKey(t *testing.T) {
	const authJSON = `{"auth":{"identity":{"sub":"alice","org":null,"nickname":""}}}`

	for name, tc := range map[string]struct {
		keyTemplate expressions.Value
		want        error
	}{
		"path":                        {&json.JSONValue{Pattern: "auth.identity.sub"}, nil},
		"template":                    {&json.JSONValue{Pattern: "user-{auth.identity.sub}"}, nil},
		"CEL list":                    {celKeyTemplate(t, `[auth.identity.sub, "x"]`), nil},
		"missing path":                {&json.JSONValue{Pattern: "auth.identity.email"}, errNullCacheKey},
		"empty static value":          {&json.JSONValue{}, errNullCacheKey},
		"template, missing":           {&json.JSONValue{Pattern: "user-{auth.identity.email}"}, errMissingPlaceholderCacheKey},
		"template, null placeholder":  {&json.JSONValue{Pattern: "user-{auth.identity.org}"}, errMissingPlaceholderCacheKey},
		"template, no path in braces": {&json.JSONValue{Pattern: "user-{}"}, errMissingPlaceholderCacheKey},
		"template, unterminated":      {&json.JSONValue{Pattern: "user-{auth.identity.sub"}, errMissingPlaceholderCacheKey},
		"empty string":                {&json.JSONValue{Pattern: "auth.identity.nickname"}, errEmptyCacheKey},
		"empty string from CEL":       {celKeyTemplate(t, `auth.identity.nickname`), errEmptyCacheKey},
		"null from CEL":               {celKeyTemplate(t, `auth.identity.org`), errNullCacheKey},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := resolveCacheKey(tc.keyTemplate, authJSON)
			if tc.want == nil {
				assert.NilError(t, err)
				assert.Assert(t, key != "")
				return
			}
			assert.Assert(t, errors.Is(err, tc.want), err)
		})
	}

	t.Run("CEL runtime error", func(t *testing.T) {
		_, err := resolveCacheKey(celKeyTemplate(t, `{"k": "v"}[auth.identity.sub]`), authJSON)
		assert.ErrorContains(t, err, "no such key")
	})
}

// newTestEvaluatorCache returns a 1 MB evaluator cache, the default size.
func newTestEvaluatorCache(t *testing.T, keyTemplate expressions.Value) EvaluatorCache {
	t.Helper()
	previous := EvaluatorCacheSize
	t.Cleanup(func() { EvaluatorCacheSize = previous })
	EvaluatorCacheSize = 1
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
