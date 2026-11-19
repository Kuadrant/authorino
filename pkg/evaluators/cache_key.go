package evaluators

import (
	"crypto/sha256"
	gojson "encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/json"
)

var (
	// errMissingPlaceholderCacheKey is returned for a template with a placeholder that renders empty, names no path or
	// is left open.
	errMissingPlaceholderCacheKey = errors.New("cache key template has a missing placeholder")
	// errNullCacheKey is returned for a key that is null or selects nothing, e.g. an empty static value.
	errNullCacheKey = errors.New("cache key is null")
	// errEmptyCacheKey is returned for an empty string, array or object.
	errEmptyCacheKey = errors.New("cache key is empty")
	// errInvalidUTF8CacheKey is returned for a non-string key with invalid UTF-8, which the JSON encoding would replace
	// with U+FFFD, so different keys would share an entry.
	errInvalidUTF8CacheKey = errors.New("cache key is not valid UTF-8")
)

// resolveCacheKey resolves the cache key for the Authorization JSON and encodes it with cacheKey. A key that is missing
// part of its source is an error, so that requests that lack it do not share an entry.
func resolveCacheKey(keyTemplate expressions.Value, authJSON string) (string, error) {
	var resolved any
	if template, ok := keyTemplate.(*json.JSONValue); ok {
		var complete bool
		if resolved, complete = template.LookupFor(authJSON); !complete {
			if template.IsTemplate() {
				return "", errMissingPlaceholderCacheKey
			}
			return "", errNullCacheKey
		}
	} else {
		var err error
		if resolved, err = keyTemplate.ResolveFor(authJSON); err != nil {
			return "", err
		}
	}
	return cacheKey(resolved)
}

// cacheKey encodes a key so that different values never share an entry and no key takes more than sha256.Size bytes:
// a string as stringCacheKey returns it, any other value as the SHA-256 of its JSON encoding (which sorts object keys),
// tagged 'j'. Null and empty keys are errors.
func cacheKey(resolved any) (string, error) {
	switch v := resolved.(type) {
	case nil:
		return "", errNullCacheKey
	case string:
		if v == "" {
			return "", errEmptyCacheKey
		}
		return stringCacheKey(v), nil
	case []any:
		if len(v) == 0 {
			return "", errEmptyCacheKey
		}
	case map[string]any:
		if len(v) == 0 {
			return "", errEmptyCacheKey
		}
	}
	if !validUTF8(resolved) {
		return "", errInvalidUTF8CacheKey
	}
	encoded, err := gojson.Marshal(resolved)
	if err != nil {
		return "", err
	}
	digester := sha256.New()
	digester.Write([]byte{'j'})
	digester.Write(encoded)
	return string(digester.Sum(nil)), nil
}

// stringCacheKey replaces a string key of sha256.Size bytes or more with its raw SHA-256. A long key then takes 32 bytes
// of the freecache entry size limit, and a long credential such as a token is not kept in the cache. A shorter key is
// kept, so that no key grows and every entry that fit before still fits. It cannot equal a digest, which is always
// sha256.Size bytes. The 's' tag keeps string digests apart from those of other keys.
func stringCacheKey(s string) string {
	if len(s) < sha256.Size {
		return s
	}
	digester := sha256.New()
	digester.Write([]byte{'s'})
	_, _ = io.WriteString(digester, s)
	return string(digester.Sum(nil))
}

// validUTF8 reports whether every string and object key in a JSON-like value is valid UTF-8.
func validUTF8(value any) bool {
	switch v := value.(type) {
	case string:
		return utf8.ValidString(v)
	case []any:
		for _, item := range v {
			if !validUTF8(item) {
				return false
			}
		}
	case map[string]any:
		for key, item := range v {
			if !utf8.ValidString(key) || !validUTF8(item) {
				return false
			}
		}
	}
	return true
}
