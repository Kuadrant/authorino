package evaluators

import (
	"crypto/sha256"
	gojson "encoding/json"
	"fmt"
	"io"
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

// ResolveKeyFor returns a long string key as its digest (see stringCacheKey). Other values are returned as they are,
// and gocache hashes them.
func (c *evaluatorCache) ResolveKeyFor(authJSON string) (interface{}, error) {
	key, err := c.keyTemplate.ResolveFor(authJSON)
	if s, ok := key.(string); ok {
		return stringCacheKey(s), err
	}
	return key, err
}

// stringCacheKey replaces a string key of sha256.Size bytes or more with its raw SHA-256, which gocache stores as it
// is. A long key then takes 32 bytes of the freecache entry size limit, and a long credential such as a token is
// neither stored nor quoted in store errors. A shorter key is kept, so that no key grows and every entry that fit
// before still fits. It cannot equal a digest, which is always sha256.Size bytes. The 's' tag keeps string digests
// apart from hashes of keys of other types.
func stringCacheKey(s string) string {
	if len(s) < sha256.Size {
		return s
	}
	digester := sha256.New()
	digester.Write([]byte{'s'})
	_, _ = io.WriteString(digester, s)
	return string(digester.Sum(nil))
}

func (c *evaluatorCache) Shutdown() error {
	return c.store.Clear()
}
