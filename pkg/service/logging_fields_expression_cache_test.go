package service

import (
	"sync"
	"testing"

	gotestassert "gotest.tools/assert"
)

func TestLoggingFieldExpressionCache(t *testing.T) {
	cache := newLoggingFieldExpressionCache(2)

	first, err := cache.getOrCompile("request.method")
	gotestassert.NilError(t, err)

	cached, err := cache.getOrCompile("request.method")
	gotestassert.NilError(t, err)
	gotestassert.Assert(t, first == cached, "expected the compiled expression to be cached")

	_, err = cache.getOrCompile("request.host")
	gotestassert.NilError(t, err)
	_, err = cache.getOrCompile("auth.identity")
	gotestassert.NilError(t, err)
	gotestassert.Equal(t, len(cache.entries), 2)

	recompiled, err := cache.getOrCompile("request.method")
	gotestassert.NilError(t, err)
	gotestassert.Assert(t, first != recompiled, "expected the least-recently-used expression to be evicted")
}

func TestLoggingFieldExpressionCacheCachesCompilationErrors(t *testing.T) {
	cache := newLoggingFieldExpressionCache(2)

	_, firstErr := cache.getOrCompile("request.")
	gotestassert.ErrorContains(t, firstErr, "Syntax error")
	_, cachedErr := cache.getOrCompile("request.")
	gotestassert.Assert(t, firstErr == cachedErr, "expected the compilation error to be cached")
}

func TestLoggingFieldExpressionCacheConcurrentAccess(t *testing.T) {
	cache := newLoggingFieldExpressionCache(2)
	expected, err := cache.getOrCompile("request.method")
	gotestassert.NilError(t, err)

	const workers = 20
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			expression, compileErr := cache.getOrCompile("request.method")
			results <- compileErr == nil && expression == expected
		}()
	}
	wg.Wait()
	close(results)

	for cached := range results {
		gotestassert.Assert(t, cached, "expected concurrent callers to receive the cached expression")
	}
}
