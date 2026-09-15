package cel

import (
	"container/list"
	"sync"
)

type expressionCacheEntry struct {
	source     string
	expression *Expression
	err        error
}

// ExpressionCache is a concurrency-safe, bounded LRU cache of compiled CEL expressions.
type ExpressionCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]*list.Element
	lru      *list.List
}

// NewExpressionCache creates an expression cache with the given maximum number of entries.
func NewExpressionCache(capacity int) *ExpressionCache {
	return &ExpressionCache{
		capacity: capacity,
		entries:  make(map[string]*list.Element, capacity),
		lru:      list.New(),
	}
}

// GetOrCompile returns a cached expression or compiles and caches it.
func (c *ExpressionCache) GetOrCompile(source string) (*Expression, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.entries[source]; ok {
		c.lru.MoveToFront(element)
		entry := element.Value.(*expressionCacheEntry)
		return entry.expression, entry.err
	}

	expression, err := NewExpression(source)
	entry := &expressionCacheEntry{source: source, expression: expression, err: err}
	element := c.lru.PushFront(entry)
	c.entries[source] = element

	if c.lru.Len() > c.capacity {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.entries, oldest.Value.(*expressionCacheEntry).source)
	}

	return expression, err
}
