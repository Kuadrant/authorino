package evaluators

import (
	gojson "encoding/json"
	"time"

	"github.com/kuadrant/authorino/pkg/json"

	"github.com/coocood/freecache"
	gocache "github.com/eko/gocache/cache"
	cache_store "github.com/eko/gocache/store"
)

var MetadataCacheSize int // in megabytes

type MetadataCache interface {
	Get(key interface{}) (interface{}, error)
	Set(key, value interface{}) error
	ResolveKeyFor(authJSON string) interface{}
	Shutdown() error
}

func NewMetadataCache(keyTemplate json.JSONValue, ttl int) MetadataCache {
	duration := time.Duration(ttl) * time.Second
	cacheClient := freecache.NewCache(MetadataCacheSize * 1024 * 1024)
	cacheStore := cache_store.NewFreecache(cacheClient, &cache_store.Options{Expiration: duration})
	c := &jsonCache{
		keyTemplate: keyTemplate,
		store:       gocache.New(cacheStore),
	}
	return c
}

// jsonCache caches JSON values (objects, arrays, strings, etc)
type jsonCache struct {
	keyTemplate json.JSONValue
	store       *gocache.Cache
}

func (c *jsonCache) Get(key interface{}) (interface{}, error) {
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

func (c *jsonCache) Set(key, value interface{}) error {
	if valueAsBytes, err := gojson.Marshal(value); err != nil {
		return err
	} else {
		return c.store.Set(key, valueAsBytes, nil)
	}
}

func (c *jsonCache) ResolveKeyFor(authJSON string) interface{} {
	return c.keyTemplate.ResolveFor(authJSON)
}

func (c *jsonCache) Shutdown() error {
	return c.store.Clear()
}
