package cache

import (
	"fmt"
	"sync"

	"github.com/kuadrant/authorino/pkg/evaluators"
)

type Cache interface {
	Set(id string, key string, config evaluators.AuthConfig, override bool) error
	Get(key string) *evaluators.AuthConfig
	Delete(id string)

	FindId(key string) (id string, found bool)
	FindKeys(id string) []string
}

type cacheEntry struct {
	Id         string
	AuthConfig evaluators.AuthConfig
}

type AuthConfigsCache struct {
	// TODO: move to RWMutex?
	mu      sync.Mutex
	entries map[string]cacheEntry
	keys    map[string][]string
}

func NewCache() Cache {
	return &AuthConfigsCache{
		mu:      sync.Mutex{},
		entries: make(map[string]cacheEntry),
		keys:    make(map[string][]string),
	}
}

func (c *AuthConfigsCache) Get(key string) *evaluators.AuthConfig {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[key]; ok {
		return &entry.AuthConfig
	} else {
		return nil
	}
}

func (c *AuthConfigsCache) Set(id string, key string, config evaluators.AuthConfig, override bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[key]; !ok || override {
		c.entries[key] = cacheEntry{
			Id:         id,
			AuthConfig: config,
		}
	} else {
		return fmt.Errorf("service already exists in cache: %s", key)
	}
	c.keys[id] = append(c.keys[id], key)

	return nil
}

func (c *AuthConfigsCache) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, configName := range c.keys[id] {
		delete(c.entries, configName)
	}
}

func (c *AuthConfigsCache) FindId(key string) (id string, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[key]; ok {
		return entry.Id, true
	} else {
		return "", false
	}
}

func (c *AuthConfigsCache) FindKeys(id string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.keys[id]
}
