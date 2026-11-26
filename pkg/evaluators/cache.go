package evaluators

import (
	"crypto/sha256"
	gojson "encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/kuadrant/authorino/pkg/expressions"

	"github.com/coocood/freecache"
	gocache "github.com/eko/gocache/cache"
	cache_store "github.com/eko/gocache/store"
)

var EvaluatorCacheSize int // in megabytes

var (
	// errCacheKeyNotFound is returned when the key, or a placeholder of its template, selects nothing, names no path or
	// is left open, so that requests that lack part of the key do not share an entry.
	errCacheKeyNotFound = errors.New("cache key selects nothing")
	// errInvalidUTF8CacheKey is returned for a key with invalid UTF-8, which the JSON encoding would replace with U+FFFD,
	// so different keys would share an entry.
	errInvalidUTF8CacheKey = errors.New("cache key is not valid UTF-8")
)

// freecache splits a cache into 256 segments, of at least 512 KB in all, and rejects an entry, key and value, larger
// than a quarter of a segment less its header, or with a key larger than 65535 bytes.
const (
	freecacheSegments   = 256
	freecacheMinSize    = 512 * 1024
	freecacheMaxKeySize = 65535
)

type EvaluatorCache interface {
	Get(key interface{}) (interface{}, error)
	Set(key, value interface{}) error
	ResolveKeyFor(authJSON string) (interface{}, error)
	Shutdown() error
}

func NewEvaluatorCache(keyTemplate expressions.Value, ttl int) EvaluatorCache {
	duration := time.Duration(ttl) * time.Second
	size := EvaluatorCacheSize * 1024 * 1024
	cacheClient := freecache.NewCache(size)
	cacheStore := cache_store.NewFreecache(cacheClient, &cache_store.Options{Expiration: duration})
	c := &evaluatorCache{
		resolveKey:   keyResolver(keyTemplate),
		maxEntrySize: max(size, freecacheMinSize)/freecacheSegments/4 - freecache.ENTRY_HDR_SIZE,
		store:        gocache.New(cacheStore),
	}
	return c
}

// keyResolver resolves the key with expressions.Lookup when the key template implements it, so that a key whose source
// selects nothing is an error, as a missing key is for a CEL expression.
func keyResolver(keyTemplate expressions.Value) func(authJSON string) (any, error) {
	lookup, ok := keyTemplate.(expressions.Lookup)
	if !ok {
		return func(authJSON string) (any, error) {
			return keyTemplate.ResolveFor(authJSON)
		}
	}
	return func(authJSON string) (any, error) {
		if value, found := lookup.LookupFor(authJSON); found {
			return value, nil
		}
		return nil, errCacheKeyNotFound
	}
}

// evaluatorCache caches JSON values (objects, arrays, strings, etc)
type evaluatorCache struct {
	resolveKey   func(authJSON string) (any, error)
	maxEntrySize int
	store        *gocache.Cache
}

func (c *evaluatorCache) Get(key interface{}) (interface{}, error) {
	if valueAsBytes, ttl, _ := c.store.GetWithTTL(key); valueAsBytes != nil && ttl > 0 {
		var value interface{}
		if err := gojson.Unmarshal(valueAsBytes.([]byte), &value); err != nil {
			return nil, err
		} else {
			return value, nil
		}
	}

	return nil, nil
}

// Set returns errors that never include the key, which may hold a credential.
func (c *evaluatorCache) Set(key, value interface{}) error {
	valueAsBytes, err := gojson.Marshal(value)
	if err != nil {
		return err
	}
	// The freecache store of gocache quotes the key in its errors, and freecache rejects an entry only for its size.
	if err := c.store.Set(key, valueAsBytes, nil); err != nil {
		keyAsString, _ := key.(string)
		if len(keyAsString) > freecacheMaxKeySize {
			return fmt.Errorf("cache entry not stored, its key of %d bytes is larger than %d bytes", len(keyAsString), freecacheMaxKeySize)
		}
		return fmt.Errorf("cache entry of %d bytes not stored, larger than the limit of %d bytes", len(keyAsString)+len(valueAsBytes), c.maxEntrySize)
	}
	return nil
}

// ResolveKeyFor returns the cache key for the Authorization JSON, encoded by cacheKey, or nil and the error when the key
// does not resolve, which callers take as no caching.
func (c *evaluatorCache) ResolveKeyFor(authJSON string) (interface{}, error) {
	resolved, err := c.resolveKey(authJSON)
	if err != nil {
		return nil, err
	}
	key, err := cacheKey(resolved)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *evaluatorCache) Shutdown() error {
	return c.store.Clear()
}

// hashedCacheKeyTag starts every cache key that is not a string. A string key is its JSON encoding, which starts with a
// quote, so the two kinds of key never meet.
const hashedCacheKeyTag = "#"

// cacheKey encodes a resolved key so that keys of different types, such as "1" and 1, or with different parts never
// share an entry. A string key is its JSON encoding, which the store compares in full. Any other key, a template's
// placeholder values included, is hashedCacheKeyTag and the SHA-256 of its JSON encoding, which sorts object keys, so
// that it takes 33 bytes of an entry however long it is, and is not kept in memory. Making a long key a list keeps it
// under the entry size limit. gocache keeps a string key as it is, and would replace any other key with the MD5 of its
// fmt text, which prints ["bob x","y"] and ["bob","x y"] alike.
func cacheKey(resolved any) (string, error) {
	if !validUTF8(resolved) {
		return "", errInvalidUTF8CacheKey
	}
	encoded, err := gojson.Marshal(resolved)
	if err != nil {
		return "", err
	}
	if _, isString := resolved.(string); isString {
		return string(encoded), nil
	}
	digest := sha256.Sum256(encoded)
	return hashedCacheKeyTag + string(digest[:]), nil
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
