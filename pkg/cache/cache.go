package cache

import (
	"fmt"
	"sync"

	"github.com/kuadrant/authorino/pkg/config"
)

type cacheEntry struct {
	Key       string
	APIConfig config.APIConfig
}

type Cache struct {
	// TODO: move to RWMutex?
	mu                 sync.Mutex
	keyHostMapping     map[string][]string
	hostConfigsMapping map[string]cacheEntry
}

func NewCache() Cache {
	return Cache{
		mu:                 sync.Mutex{},
		keyHostMapping:     make(map[string][]string),
		hostConfigsMapping: make(map[string]cacheEntry),
	}
}

func (c *Cache) Get(host string) *config.APIConfig {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.hostConfigsMapping[host]; ok {
		return &entry.APIConfig
	} else {
		return nil
	}
}

func (c *Cache) Set(key string, host string, config config.APIConfig, override bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.hostConfigsMapping[host]; !ok || override {
		c.hostConfigsMapping[host] = cacheEntry{
			Key:       key,
			APIConfig: config,
		}
	} else {
		return fmt.Errorf("service already exists in cache: %s", host)
	}
	c.keyHostMapping[key] = append(c.keyHostMapping[key], host)

	return nil
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, configName := range c.keyHostMapping[key] {
		delete(c.hostConfigsMapping, configName)
	}
}

func (c *Cache) Hosts(key string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.keyHostMapping[key]
}

func (c *Cache) Key(host string) *string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.hostConfigsMapping[host]; ok {
		return &entry.Key
	} else {
		return nil
	}
}
