package evaluators

import (
	gojson "encoding/json"
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

func (c *evaluatorCache) Set(key, value interface{}) error {
	if valueAsBytes, err := gojson.Marshal(value); err != nil {
		return err
	} else {
		return c.store.Set(key, valueAsBytes, nil)
	}
}

func (c *evaluatorCache) ResolveKeyFor(authJSON string) (interface{}, error) {
	return c.keyTemplate.ResolveFor(authJSON)
}

func (c *evaluatorCache) Shutdown() error {
	return c.store.Clear()
}
