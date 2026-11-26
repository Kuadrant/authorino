package evaluators

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/expressions/cel"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/metrics"

	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
	"k8s.io/apimachinery/pkg/types"
)

const testCacheAuthJSON = `{"auth":{"identity":{"sub":"alice","group":"admins"}}}`

var testCacheOwner = types.NamespacedName{Namespace: "default", Name: "talker-api"}

type testCacheEvaluatorConfig struct {
	metrics bool
}

func (testCacheEvaluatorConfig) GetType() string        { return metadataGenericHTTP }
func (testCacheEvaluatorConfig) GetName() string        { return "user-info" }
func (c testCacheEvaluatorConfig) MetricsEnabled() bool { return c.metrics }

func TestEvaluatorCacheHit(t *testing.T) {
	cacheMetrics := freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	ctx := t.Context()
	evaluator.EXPECT().Call(pipeline, ctx).Return(map[string]any{"foo": "bar"}, nil).Times(1)

	cache := NewEvaluatorCache(&json.JSONValue{Pattern: "auth.identity.sub"}, 60, testCacheOwner)
	config := testCacheEvaluatorConfig{metrics: true}

	for range 2 {
		obj, err := cache.Call(ctx, pipeline, config, evaluator)
		assert.NilError(t, err)
		assert.DeepEqual(t, obj, map[string]any{"foo": "bar"})
	}

	labels := `{authconfig="talker-api",evaluator_name="user-info",evaluator_type="METADATA_GENERIC_HTTP",namespace="default"}`
	assert.NilError(t, testutil.CollectAndCompare(cacheMetrics.miss, strings.NewReader(
		"# HELP auth_server_evaluator_cache_miss test\n# TYPE auth_server_evaluator_cache_miss counter\nauth_server_evaluator_cache_miss"+labels+" 1\n")))
	assert.NilError(t, testutil.CollectAndCompare(cacheMetrics.hit, strings.NewReader(
		"# HELP auth_server_evaluator_cache_hit test\n# TYPE auth_server_evaluator_cache_hit counter\nauth_server_evaluator_cache_hit"+labels+" 1\n")))
	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.storeFailed), 0)
	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.keyUnresolved), 0)
}

func TestEvaluatorCacheHitWithNonStringKey(t *testing.T) {
	freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return("ok", nil).Times(1)

	cache := NewEvaluatorCache(&json.JSONValue{Pattern: "auth.identity"}, 60, testCacheOwner)

	for range 2 {
		obj, err := cache.Call(t.Context(), pipeline, testCacheEvaluatorConfig{}, evaluator)
		assert.NilError(t, err)
		assert.Equal(t, obj, "ok")
	}
}

func TestEvaluatorCacheSelectorWithCEL(t *testing.T) {
	cacheMetrics := freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return("ok", nil).Times(3)

	// CEL under selector is read as a JSON path and resolves to null
	cache := NewEvaluatorCache(&json.JSONValue{Pattern: `auth.identity.sub + "x"`}, 60, testCacheOwner)
	logs := captureLogs(t, 0)

	for range 3 {
		obj, err := cache.Call(logs.ctx, pipeline, testCacheEvaluatorConfig{metrics: true}, evaluator)
		assert.NilError(t, err)
		assert.Equal(t, obj, "ok")
	}

	lines := logs.matching("evaluator cache key did not resolve, not cached")
	assert.Equal(t, len(lines), 1, logs.lines)
	assert.Assert(t, strings.Contains(lines[0], `"authconfig"="default/talker-api"`), lines[0])
	assert.Assert(t, strings.Contains(lines[0], `"evaluator"="user-info"`), lines[0])
	assert.Assert(t, strings.Contains(lines[0], `"keySource"="selector"`), lines[0])
	assert.Assert(t, strings.Contains(lines[0], "a CEL expression goes under cache.key.expression"), lines[0])
	assert.Assert(t, strings.Contains(lines[0], `"reason"="null"`), lines[0])
	assert.Equal(t, testutil.ToFloat64(cacheMetrics.keyUnresolved), float64(3))
	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.miss), 0)
}

func TestEvaluatorCacheExpressionError(t *testing.T) {
	cacheMetrics := freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return("ok", nil).Times(2)

	// the CEL runtime error ("no such key: alice") carries a value from the request
	cache := NewEvaluatorCache(mustCELExpression(t, `{"bob": "x"}[auth.identity.sub]`), 60, testCacheOwner)
	logs := captureLogs(t, 1)

	for range 2 {
		_, err := cache.Call(logs.ctx, pipeline, testCacheEvaluatorConfig{metrics: true}, evaluator)
		assert.NilError(t, err)
	}

	lines := logs.matching("evaluator cache key did not resolve, not cached")
	assert.Equal(t, len(lines), 1, logs.lines)
	assert.Assert(t, strings.Contains(lines[0], `"keySource"="expression"`), lines[0])
	assert.Assert(t, !strings.Contains(lines[0], "alice"), lines[0])
	assert.Assert(t, !strings.Contains(lines[0], "hint"), lines[0])
	assert.Assert(t, strings.Contains(lines[0], `"reason"="error"`), lines[0])
	debugLines := logs.matching("evaluator cache key did not resolve")
	assert.Equal(t, len(debugLines), 2, logs.lines)
	assert.Assert(t, strings.Contains(debugLines[0], `"level"=1`), debugLines[0])
	assert.Assert(t, strings.Contains(debugLines[0], "no such key"), debugLines[0])
	assert.Equal(t, testutil.ToFloat64(cacheMetrics.keyUnresolved), float64(2))
}

func TestEvaluatorCacheEntryTooLarge(t *testing.T) {
	cacheMetrics := freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return(strings.Repeat("x", 1200), nil).Times(2)

	const secretKey = "api-key-do-not-log-me"
	cache := NewEvaluatorCache(&json.JSONValue{Static: secretKey}, 60, testCacheOwner)
	logs := captureLogs(t, 1) // debug lines must not carry the key either

	for range 2 {
		_, err := cache.Call(logs.ctx, pipeline, testCacheEvaluatorConfig{metrics: true}, evaluator)
		assert.NilError(t, err)
	}

	lines := logs.matching("evaluator cache entry too large, not cached")
	assert.Equal(t, len(lines), 1, logs.lines)
	assert.Assert(t, strings.Contains(lines[0], `"entrySize"=1223`), lines[0]) // 21 B key + 1202 B JSON string
	assert.Assert(t, strings.Contains(lines[0], `"limit"=1000`), lines[0])
	assert.Assert(t, strings.Contains(lines[0], `"authconfig"="default/talker-api"`), lines[0])
	assert.Assert(t, strings.Contains(lines[0], `"evaluator"="user-info"`), lines[0])
	assert.Assert(t, strings.Contains(lines[0], `"evaluatorCacheSize"=1`), lines[0])
	for _, line := range logs.lines {
		assert.Assert(t, !strings.Contains(line, secretKey), line)
	}
	assert.Equal(t, testutil.ToFloat64(cacheMetrics.miss), float64(2))
	assert.Equal(t, testutil.ToFloat64(cacheMetrics.storeFailed), float64(2))
}

func TestEvaluatorCacheEntrySizeLimit(t *testing.T) {
	// the size checked before the entry reaches gocache must be the one freecache enforces: an entry at the limit is
	// stored and read back, one byte more is rejected
	for sizeInMB, limit := range map[int]int{0: 488, 1: 1000, 2: 2024, 4: 4072} {
		for name, key := range map[string]any{
			"string key":                         "k",
			"list key, stored as a 32-byte hash": []any{"k"},
		} {
			t.Run(fmt.Sprintf("%dMB, %s", sizeInMB, name), func(t *testing.T) {
				withEvaluatorCacheSize(t, sizeInMB)
				cache := NewEvaluatorCache(&json.JSONValue{Static: "k"}, 60, testCacheOwner).(*evaluatorCache)
				assert.Equal(t, cache.maxEntrySize, limit)

				// a JSON string value is 2 bytes longer than the string
				atLimit := strings.Repeat("x", limit-storedKeySize(key)-2)
				assert.NilError(t, cache.set(key, atLimit))
				cached, err := cache.get(key)
				assert.NilError(t, err)
				assert.Equal(t, cached, atLimit)

				err = cache.set(key, atLimit+"x")
				tooLarge, ok := errors.AsType[*cacheEntryTooLargeError](err)
				assert.Assert(t, ok, err)
				assert.Equal(t, tooLarge.size, limit+1)
			})
		}
	}
}

func TestEvaluatorCacheKeyTooLarge(t *testing.T) {
	cacheMetrics := freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return("ok", nil).Times(2)

	// freecache rejects keys over 65535 bytes before it checks the entry size
	secretKey := strings.Repeat("k", 65536)
	cache := NewEvaluatorCache(&json.JSONValue{Static: secretKey}, 60, testCacheOwner)
	logs := captureLogs(t, 1)

	for range 2 {
		_, err := cache.Call(logs.ctx, pipeline, testCacheEvaluatorConfig{metrics: true}, evaluator)
		assert.NilError(t, err)
	}

	lines := logs.matching("evaluator cache failed to store entry, not cached")
	assert.Equal(t, len(lines), 1, logs.lines)
	assert.Assert(t, strings.Contains(lines[0], `"reason"="cache key larger than 65535 bytes"`), lines[0])
	for _, line := range logs.lines {
		assert.Assert(t, !strings.Contains(line, secretKey[:32]), line)
	}
	assert.Equal(t, testutil.ToFloat64(cacheMetrics.storeFailed), float64(2))
}

func TestEvaluatorCacheKeepsKeysApart(t *testing.T) {
	for name, keyTemplate := range map[string]expressions.Value{
		"string key": &json.JSONValue{Pattern: "auth.identity.sub"},
		"object key": &json.JSONValue{Pattern: "auth.identity"},
	} {
		t.Run(name, func(t *testing.T) {
			freshCacheMetrics(t)
			withEvaluatorCacheSize(t, 1)

			mockctrl := gomock.NewController(t)
			alice := mockPipelineFor(mockctrl, `{"auth":{"identity":{"sub":"alice"}}}`)
			bob := mockPipelineFor(mockctrl, `{"auth":{"identity":{"sub":"bob"}}}`)
			evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
			evaluator.EXPECT().Call(alice, gomock.Any()).Return("for alice", nil).Times(1)
			evaluator.EXPECT().Call(bob, gomock.Any()).Return("for bob", nil).Times(1)

			cache := NewEvaluatorCache(keyTemplate, 60, testCacheOwner)

			for _, call := range []struct {
				pipeline *mock_auth.MockAuthPipeline
				want     string
			}{{alice, "for alice"}, {bob, "for bob"}, {alice, "for alice"}, {bob, "for bob"}} {
				obj, err := cache.Call(t.Context(), call.pipeline, testCacheEvaluatorConfig{}, evaluator)
				assert.NilError(t, err)
				assert.Equal(t, obj, call.want)
			}
		})
	}
}

func TestEvaluatorCacheDoesNotCacheErrors(t *testing.T) {
	cacheMetrics := freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	upstreamErr := errors.New("upstream unavailable")
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return("partial", upstreamErr).Times(2)

	cache := NewEvaluatorCache(&json.JSONValue{Pattern: "auth.identity.sub"}, 60, testCacheOwner)

	for range 2 {
		obj, err := cache.Call(t.Context(), pipeline, testCacheEvaluatorConfig{metrics: true}, evaluator)
		assert.Assert(t, errors.Is(err, upstreamErr), err)
		assert.Equal(t, obj, "partial")
	}

	assert.Equal(t, testutil.ToFloat64(cacheMetrics.miss), float64(2))
	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.hit), 0)
	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.storeFailed), 0)
}

func TestEvaluatorCacheReevaluatesNull(t *testing.T) {
	freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return(nil, nil).Times(2)

	cache := NewEvaluatorCache(&json.JSONValue{Pattern: "auth.identity.sub"}, 60, testCacheOwner)

	for range 2 {
		obj, err := cache.Call(t.Context(), pipeline, testCacheEvaluatorConfig{}, evaluator)
		assert.NilError(t, err)
		assert.Assert(t, obj == nil)
	}
}

func TestEvaluatorCacheNonPositiveTTL(t *testing.T) {
	cacheMetrics := freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return("ok", nil).Times(3)

	// freecache keeps entries with a TTL <= 0 forever
	cache := NewEvaluatorCache(&json.JSONValue{Pattern: "auth.identity.sub"}, -1, testCacheOwner)
	logs := captureLogs(t, 0)

	for range 3 {
		_, err := cache.Call(logs.ctx, pipeline, testCacheEvaluatorConfig{metrics: true}, evaluator)
		assert.NilError(t, err)
	}

	lines := logs.matching("evaluator cache ttl is not positive, not cached")
	assert.Equal(t, len(lines), 1, logs.lines)
	assert.Assert(t, strings.Contains(lines[0], `"ttl"=-1`), lines[0])
	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.hit), 0)
	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.miss), 0)
}

func TestEvaluatorCacheRedactsResolveError(t *testing.T) {
	// the CEL runtime error quotes the looked-up value: "no such key: <value>"
	for name, tc := range map[string]struct{ authJSON, expression, secret string }{
		"sensitive header": {
			`{"request":{"headers":{"authorization":"Bearer s3cr3t-token"}}}`,
			`{"k": "v"}[request.headers.authorization]`,
			"s3cr3t",
		},
		"token inside an array": {
			`{"auth":{"identity":{"credentials":[{"token":"s3cr3t-token"}]}}}`,
			`{"k": "v"}[auth.identity.credentials[0].token]`,
			"s3cr3t",
		},
		"field not known as sensitive": {
			`{"auth":{"identity":{"nickname":"s3cr3t-nick"}}}`,
			`{"k": "v"}[auth.identity.nickname]`,
			"s3cr3t",
		},
		"number": {
			`{"auth":{"identity":{"pin":482913}}}`,
			`{"k": "v"}[string(auth.identity.pin)]`,
			"482913",
		},
		"number used as a key": {
			`{"auth":{"identity":{"pin":482913}}}`,
			`{1: "v"}[auth.identity.pin]`,
			"482913",
		},
	} {
		t.Run(name, func(t *testing.T) {
			// given
			freshCacheMetrics(t)
			withEvaluatorCacheSize(t, 1)
			mockctrl := gomock.NewController(t)
			pipeline := mockPipelineFor(mockctrl, tc.authJSON)
			evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
			evaluator.EXPECT().Call(pipeline, gomock.Any()).Return("ok", nil).Times(1)
			expression := mustCELExpression(t, tc.expression)
			_, rawErr := expression.ResolveFor(tc.authJSON)
			assert.ErrorContains(t, rawErr, tc.secret)
			cache := NewEvaluatorCache(expression, 60, testCacheOwner)
			logs := captureLogs(t, 1)

			// when
			_, err := cache.Call(logs.ctx, pipeline, testCacheEvaluatorConfig{}, evaluator)
			assert.NilError(t, err)

			// then
			debugLines := logs.matching("evaluator cache key did not resolve")
			assert.Equal(t, len(debugLines), 1, logs.lines)
			assert.Assert(t, strings.Contains(debugLines[0], "no such key"), debugLines[0])
			for _, line := range logs.lines {
				assert.Assert(t, !strings.Contains(line, tc.secret), line)
			}
		})
	}
}

func TestEvaluatorCacheMetricsDisabled(t *testing.T) {
	cacheMetrics := freshCacheMetrics(t)
	withEvaluatorCacheSize(t, 1)

	mockctrl := gomock.NewController(t)
	pipeline := mockPipeline(mockctrl)
	evaluator := mock_auth.NewMockAuthConfigEvaluator(mockctrl)
	evaluator.EXPECT().Call(pipeline, gomock.Any()).Return("ok", nil).Times(1)

	cache := NewEvaluatorCache(&json.JSONValue{Pattern: "auth.identity.sub"}, 60, testCacheOwner)

	for range 2 {
		_, err := cache.Call(t.Context(), pipeline, testCacheEvaluatorConfig{metrics: false}, evaluator)
		assert.NilError(t, err)
	}

	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.hit), 0)
	assert.Equal(t, testutil.CollectAndCount(cacheMetrics.miss), 0)
}

type testCacheMetrics struct {
	hit, miss, keyUnresolved, storeFailed *metrics.DynamicCounter
}

// freshCacheMetrics swaps the package-level cache counters for unregistered ones, so each test reads only its own counts.
func freshCacheMetrics(t *testing.T) testCacheMetrics {
	t.Helper()
	hit, miss, keyUnresolved, storeFailed := authServerEvaluatorCacheHitMetric, authServerEvaluatorCacheMissMetric, authServerEvaluatorCacheKeyUnresolvedMetric, authServerEvaluatorCacheStoreFailedMetric
	t.Cleanup(func() {
		authServerEvaluatorCacheHitMetric, authServerEvaluatorCacheMissMetric, authServerEvaluatorCacheKeyUnresolvedMetric, authServerEvaluatorCacheStoreFailedMetric = hit, miss, keyUnresolved, storeFailed
	})

	fresh := testCacheMetrics{
		hit:           metrics.NewDynamicCounter("auth_server_evaluator_cache_hit", "test"),
		miss:          metrics.NewDynamicCounter("auth_server_evaluator_cache_miss", "test"),
		keyUnresolved: metrics.NewDynamicCounter("auth_server_evaluator_cache_key_unresolved", "test"),
		storeFailed:   metrics.NewDynamicCounter("auth_server_evaluator_cache_store_failed", "test"),
	}
	authServerEvaluatorCacheHitMetric, authServerEvaluatorCacheMissMetric, authServerEvaluatorCacheKeyUnresolvedMetric, authServerEvaluatorCacheStoreFailedMetric = fresh.hit, fresh.miss, fresh.keyUnresolved, fresh.storeFailed
	return fresh
}

func withEvaluatorCacheSize(t *testing.T, sizeInMB int) {
	t.Helper()
	previous := EvaluatorCacheSize
	t.Cleanup(func() { EvaluatorCacheSize = previous })
	EvaluatorCacheSize = sizeInMB
}

func mockPipeline(mockctrl *gomock.Controller) *mock_auth.MockAuthPipeline {
	return mockPipelineFor(mockctrl, testCacheAuthJSON)
}

func mockPipelineFor(mockctrl *gomock.Controller, authJSON string) *mock_auth.MockAuthPipeline {
	pipeline := mock_auth.NewMockAuthPipeline(mockctrl)
	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON).AnyTimes()
	return pipeline
}

func mustCELExpression(t *testing.T, source string) expressions.Value {
	t.Helper()
	expression, err := cel.NewExpression(source)
	assert.NilError(t, err)
	return expression
}

type capturedLogs struct {
	ctx   context.Context
	lines []string
}

// captureLogs returns a context whose logger records every line up to the given verbosity.
func captureLogs(t *testing.T, verbosity int) *capturedLogs {
	t.Helper()
	logs := &capturedLogs{}
	logger := funcr.New(func(_, args string) {
		logs.lines = append(logs.lines, args)
	}, funcr.Options{Verbosity: verbosity})
	logs.ctx = log.IntoContext(t.Context(), logger)
	return logs
}

func (l *capturedLogs) matching(msg string) []string {
	var out []string
	for _, line := range l.lines {
		if strings.Contains(line, `"msg"="`+msg+`"`) {
			out = append(out, line)
		}
	}
	return out
}
