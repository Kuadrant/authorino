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
	List() []*evaluators.AuthConfig

	FindId(key string) (id string, found bool)
	FindKeys(id string) []string
}

func NewCache() Cache {
	return newAuthConfigMap()
}

type cacheEntry struct {
	Id         string
	AuthConfig evaluators.AuthConfig
}

// Cache of AuthConfigs structured as a map.
// Map-based cache structures are straightforward.
// There is no support for wildcards in the keys of map-based cache structures.

func newAuthConfigMap() *authConfigMap {
	return &authConfigMap{
		mu:      sync.Mutex{},
		entries: make(map[string]cacheEntry),
		keys:    make(map[string][]string),
	}
}

type authConfigMap struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	keys    map[string][]string
}

func (c *authConfigMap) Get(key string) *evaluators.AuthConfig {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[key]; ok {
		return &entry.AuthConfig
	} else {
		return nil
	}
}

func (c *authConfigMap) Set(id string, key string, config evaluators.AuthConfig, override bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[key]; !ok || override {
		c.entries[key] = cacheEntry{
			Id:         id,
			AuthConfig: config,
		}
	} else {
		return fmt.Errorf("authconfig already exists in the cache: %s", key)
	}
	c.keys[id] = append(c.keys[id], key)

	return nil
}

func (c *authConfigMap) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, configName := range c.keys[id] {
		delete(c.entries, configName)
	}
}

func (c *authConfigMap) FindId(key string) (id string, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[key]; ok {
		return entry.Id, true
	} else {
		return "", false
	}
}

func (c *authConfigMap) FindKeys(id string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.keys[id]
}

func (c *authConfigMap) List() []*evaluators.AuthConfig {
	var authConfigs []*evaluators.AuthConfig
	for _, e := range c.entries {
		authConfigs = append(authConfigs, &e.AuthConfig)
	}
	return authConfigs
}
