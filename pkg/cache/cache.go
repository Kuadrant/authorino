package cache

import (
	"fmt"
	"sync"

	"github.com/kuadrant/authorino/pkg/config"
)

type Cache interface {
	Set(id string, key string, config config.APIConfig, override bool) error
	Get(key string) *config.APIConfig
	Delete(id string)

	FindId(key string) (id string, found bool)
	FindKeys(id string) []string
}

type cacheEntry struct {
	Id        string
	APIConfig config.APIConfig
}

type APIConfigsCache struct {
	// TODO: move to RWMutex?
	mu      sync.Mutex
	entries map[string]cacheEntry
	keys    map[string][]string
}

func NewCache() Cache {
	return &APIConfigsCache{
		mu:      sync.Mutex{},
		entries: make(map[string]cacheEntry),
		keys:    make(map[string][]string),
	}
}

func (c *APIConfigsCache) Get(key string) *config.APIConfig {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[key]; ok {
		return &entry.APIConfig
	} else {
		return nil
	}
}

func (c *APIConfigsCache) Set(id string, key string, config config.APIConfig, override bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[key]; !ok || override {
		c.entries[key] = cacheEntry{
			Id:        id,
			APIConfig: config,
		}
	} else {
		return fmt.Errorf("service already exists in cache: %s", key)
	}
	c.keys[id] = append(c.keys[id], key)

	return nil
}

func (c *APIConfigsCache) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, configName := range c.keys[id] {
		delete(c.entries, configName)
	}
}

func (c *APIConfigsCache) FindId(key string) (id string, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[key]; ok {
		return entry.Id, true
	} else {
		return "", false
	}
}

func (c *APIConfigsCache) FindKeys(id string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.keys[id]
}
