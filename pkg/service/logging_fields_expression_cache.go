package service

import (
	"container/list"
	"sync"

	"github.com/kuadrant/authorino/pkg/expressions/cel"
)

const loggingFieldExpressionCacheCapacity = 256

var loggingFieldExpressions = newLoggingFieldExpressionCache(loggingFieldExpressionCacheCapacity)

type loggingFieldExpressionCacheEntry struct {
	source     string
	expression *cel.Expression
	err        error
}

type loggingFieldExpressionCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]*list.Element
	lru      *list.List
}

func newLoggingFieldExpressionCache(capacity int) *loggingFieldExpressionCache {
	return &loggingFieldExpressionCache{
		capacity: capacity,
		entries:  make(map[string]*list.Element, capacity),
		lru:      list.New(),
	}
}

func (c *loggingFieldExpressionCache) getOrCompile(source string) (*cel.Expression, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.entries[source]; ok {
		c.lru.MoveToFront(element)
		entry := element.Value.(*loggingFieldExpressionCacheEntry)
		return entry.expression, entry.err
	}

	expression, err := cel.NewExpression(source)
	entry := &loggingFieldExpressionCacheEntry{source: source, expression: expression, err: err}
	element := c.lru.PushFront(entry)
	c.entries[source] = element

	if c.lru.Len() > c.capacity {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.entries, oldest.Value.(*loggingFieldExpressionCacheEntry).source)
	}

	return expression, err
}
