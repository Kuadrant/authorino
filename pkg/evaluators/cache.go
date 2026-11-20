package evaluators

import (
	gojson "encoding/json"
	"fmt"
	"time"

	"github.com/kuadrant/authorino/pkg/expressions"

	"github.com/coocood/freecache"
	gocache "github.com/eko/gocache/cache"
	cache_store "github.com/eko/gocache/store"
)

var EvaluatorCacheSize int // in megabytes

type EvaluatorCache interface {
	Get(key interface{}) (interface{}, error)
	Set(key, value interface{}) error
	ResolveKeyFor(authJSON string) (interface{}, error)
	Shutdown() error
}

func NewEvaluatorCache(keyTemplate expressions.Value, ttl int) EvaluatorCache {
	duration := time.Duration(ttl) * time.Second
	cacheClient := freecache.NewCache(EvaluatorCacheSize * 1024 * 1024)
	cacheStore := cache_store.NewFreecache(cacheClient, &cache_store.Options{Expiration: duration})
	c := &evaluatorCache{
		keyTemplate: keyTemplate,
		store:       gocache.New(cacheStore),
	}
	return c
}

// evaluatorCache caches JSON values (objects, arrays, strings, etc)
type evaluatorCache struct {
	keyTemplate expressions.Value
	store       *gocache.Cache
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
	// The freecache store of gocache quotes the key in its errors. Keys are at most 32 bytes here, so the store can only
	// reject an entry for its size.
	if err := c.store.Set(key, valueAsBytes, nil); err != nil {
		return fmt.Errorf("cache entry with a value of %d bytes not stored, larger than the entry size limit", len(valueAsBytes))
	}
	return nil
}

// ResolveKeyFor returns the cache key for the Authorization JSON, encoded by resolveCacheKey, or nil when the key does
// not resolve, which callers take as no caching.
func (c *evaluatorCache) ResolveKeyFor(authJSON string) (interface{}, error) {
	key, err := resolveCacheKey(c.keyTemplate, authJSON)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *evaluatorCache) Shutdown() error {
	return c.store.Clear()
}
