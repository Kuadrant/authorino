package cache

import (
	"fmt"
	"sync"

	"github.com/3scale-labs/authorino/pkg/config"
)

type Cache struct {
	// TODO: move to RWMutex?
	mu         sync.Mutex
	keyMapping map[string][]string
	apiConfigs map[string]config.APIConfig
}

func NewCache() Cache {
	return Cache{
		mu:         sync.Mutex{},
		keyMapping: make(map[string][]string),
		apiConfigs: make(map[string]config.APIConfig),
	}
}

func (c *Cache) Get(serviceHost string) config.APIConfig {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.apiConfigs[serviceHost]
}

func (c *Cache) Set(key string, serviceHost string, config config.APIConfig, override bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.apiConfigs[serviceHost]; !ok || override {
		c.apiConfigs[serviceHost] = config
	} else {
		return fmt.Errorf("service already exists in cache: %s", serviceHost)
	}
	c.keyMapping[key] = append(c.keyMapping[key], serviceHost)

	return nil
}

func (c *Cache) List() map[string]config.APIConfig {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.apiConfigs
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, configName := range c.keyMapping[key] {
		delete(c.apiConfigs, configName)
	}
}
