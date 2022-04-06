package evaluators

import (
	"context"
	gojson "encoding/json"
	"fmt"
	"time"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators/metadata"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"

	"github.com/coocood/freecache"
	gocache "github.com/eko/gocache/cache"
	cache_store "github.com/eko/gocache/store"
)

const (
	metadataUserInfo    = "METADATA_USERINFO"
	metadataUMA         = "METADATA_UMA"
	metadataGenericHTTP = "METADATA_GENERIC_HTTP"
)

var MetadataCacheSize int // in megabytes

// TODO: move to pkg/cache
func NewCache(key json.JSONValue, ttl int) *Cache {
	duration := time.Duration(ttl) * time.Second
	cacheClient := freecache.NewCache(MetadataCacheSize * 1024 * 1024)
	cacheStore := cache_store.NewFreecache(cacheClient, &cache_store.Options{Expiration: duration})
	c := &Cache{
		Key:   key,
		Store: gocache.New(cacheStore),
	}
	return c
}

type Cache struct {
	Key   json.JSONValue
	Store *gocache.Cache
}

func (c *Cache) Get(key interface{}) (interface{}, error) {
	if valueAsBytes, ttl, _ := c.Store.GetWithTTL(key); valueAsBytes != nil && ttl > 0 {
		var value interface{}
		if err := gojson.Unmarshal(valueAsBytes.([]byte), &value); err != nil {
			return nil, err
		} else {
			return value, nil
		}
	} else {
		return nil, nil
	}
}

func (c *Cache) Set(key, value interface{}) error {
	if valueAsBytes, err := gojson.Marshal(value); err != nil {
		return err
	} else {
		return c.Store.Set(key, valueAsBytes, nil)
	}
}

func (c *Cache) Shutdown() (err error) {
	return c.Store.Clear()
}

type MetadataConfig struct {
	Name       string                         `yaml:"name"`
	Priority   int                            `yaml:"priority"`
	Conditions []json.JSONPatternMatchingRule `yaml:"conditions"`
	Metrics    bool                           `yaml:"metrics"`

	UserInfo    *metadata.UserInfo    `yaml:"userinfo,omitempty"`
	UMA         *metadata.UMA         `yaml:"uma,omitempty"`
	GenericHTTP *metadata.GenericHttp `yaml:"http,omitempty"`

	Cache *Cache
}

func (config *MetadataConfig) GetAuthConfigEvaluator() auth.AuthConfigEvaluator {
	switch config.GetType() {
	case metadataUserInfo:
		return config.UserInfo
	case metadataUMA:
		return config.UMA
	case metadataGenericHTTP:
		return config.GenericHTTP
	default:
		return nil
	}
}

// impl:AuthConfigEvaluator

func (config *MetadataConfig) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator == nil {
		return nil, fmt.Errorf("invalid metadata config")
	} else {
		logger := log.FromContext(ctx).WithName("metadata").WithValues("config", config.Name)

		cache := config.Cache
		var cacheKey interface{}

		if cache != nil {
			cacheKey = cache.Key.ResolveFor(pipeline.GetAuthorizationJSON())
			if cachedObj, err := cache.Get(cacheKey); err != nil {
				logger.V(1).Error(err, "failed to retrieve data from the cache")
			} else if cachedObj != nil {
				return cachedObj, nil
			}
		}

		obj, err := evaluator.Call(pipeline, log.IntoContext(ctx, logger))

		if err == nil && cacheKey != nil {
			if err := cache.Set(cacheKey, obj); err != nil {
				logger.V(1).Info("unable to store data in the cache", "err", err)
			}
		}

		return obj, err
	}
}

// impl:NamedEvaluator

func (config *MetadataConfig) GetName() string {
	return config.Name
}

// impl:TypedEvaluator

func (config *MetadataConfig) GetType() string {
	switch {
	case config.UserInfo != nil:
		return metadataUserInfo
	case config.UMA != nil:
		return metadataUMA
	case config.GenericHTTP != nil:
		return metadataGenericHTTP
	default:
		return ""
	}
}

// impl:Prioritizable

func (config *MetadataConfig) GetPriority() int {
	return config.Priority
}

// impl:ConditionalEvaluator

func (config *MetadataConfig) GetConditions() []json.JSONPatternMatchingRule {
	return config.Conditions
}

// impl:AuthConfigCleaner

func (config *MetadataConfig) Clean(_ context.Context) error {
	if config.Cache != nil {
		return config.Cache.Shutdown()
	}
	return nil
}

// impl:metrics.Object

func (config *MetadataConfig) MetricsEnabled() bool {
	return config.Metrics
}
