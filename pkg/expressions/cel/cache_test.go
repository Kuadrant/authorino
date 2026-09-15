package cel

import (
	"sync"
	"testing"

	gotestassert "gotest.tools/assert"
)

func TestExpressionCache(t *testing.T) {
	cache := NewExpressionCache(2)

	first, err := cache.GetOrCompile("request.method")
	gotestassert.NilError(t, err)

	cached, err := cache.GetOrCompile("request.method")
	gotestassert.NilError(t, err)
	gotestassert.Assert(t, first == cached, "expected the compiled expression to be cached")

	_, err = cache.GetOrCompile("request.host")
	gotestassert.NilError(t, err)
	_, err = cache.GetOrCompile("auth.identity")
	gotestassert.NilError(t, err)
	gotestassert.Equal(t, len(cache.entries), 2)

	recompiled, err := cache.GetOrCompile("request.method")
	gotestassert.NilError(t, err)
	gotestassert.Assert(t, first != recompiled, "expected the least-recently-used expression to be evicted")
}

func TestExpressionCacheCachesCompilationErrors(t *testing.T) {
	cache := NewExpressionCache(2)

	_, firstErr := cache.GetOrCompile("request.")
	gotestassert.ErrorContains(t, firstErr, "Syntax error")
	_, cachedErr := cache.GetOrCompile("request.")
	gotestassert.Assert(t, firstErr == cachedErr, "expected the compilation error to be cached")
}

func TestExpressionCacheConcurrentAccess(t *testing.T) {
	cache := NewExpressionCache(2)
	expected, err := cache.GetOrCompile("request.method")
	gotestassert.NilError(t, err)

	const workers = 20
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			expression, compileErr := cache.GetOrCompile("request.method")
			results <- compileErr == nil && expression == expected
		}()
	}
	wg.Wait()
	close(results)

	for cached := range results {
		gotestassert.Assert(t, cached, "expected concurrent callers to receive the cached expression")
	}
}
