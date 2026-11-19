package evaluators

import (
	"context"
	gojson "encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/expressions/cel"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/metrics"

	"github.com/coocood/freecache"
	gocache "github.com/eko/gocache/cache"
	cache_store "github.com/eko/gocache/store"
	"k8s.io/apimachinery/pkg/types"
)

var EvaluatorCacheSize int // in megabytes

var (
	authServerEvaluatorCacheHitMetric           = metrics.NewDynamicCounter("auth_server_evaluator_cache_hit", "Number of evaluations of individual authconfig rule served from the evaluator cache.")
	authServerEvaluatorCacheMissMetric          = metrics.NewDynamicCounter("auth_server_evaluator_cache_miss", "Number of evaluations of individual authconfig rule not found in the evaluator cache.")
	authServerEvaluatorCacheKeyUnresolvedMetric = metrics.NewDynamicCounter("auth_server_evaluator_cache_key_unresolved", "Number of evaluations of individual authconfig rule whose cache key did not resolve, so the evaluator cache was skipped.")
	authServerEvaluatorCacheStoreFailedMetric   = metrics.NewDynamicCounter("auth_server_evaluator_cache_store_failed", "Number of evaluated objects of individual authconfig rule the evaluator cache failed to store.")
)

func init() {
	metrics.Register(
		authServerEvaluatorCacheHitMetric,
		authServerEvaluatorCacheMissMetric,
		authServerEvaluatorCacheKeyUnresolvedMetric,
		authServerEvaluatorCacheStoreFailedMetric,
	)
}

const (
	// freecache splits its capacity into 256 segments, each at least 2 KiB (512 KiB in total).
	freecacheSegments    = 256
	freecacheMinCapacity = 512 * 1024
	// freecache rejects keys longer than this.
	freecacheMaxKeySize = 65535
	// gocache stores a key that is not a string as the hex MD5 of its type and content.
	gocacheHashedKeySize = 32
)

type EvaluatorCache interface {
	// Call returns the object cached for the key resolved from the Authorization JSON or, if there is none, calls the evaluator and caches what it returns.
	// The config identifies the evaluator in logs and metrics.
	Call(ctx context.Context, pipeline auth.AuthPipeline, config metrics.Object, evaluator auth.AuthConfigEvaluator) (any, error)
	Shutdown() error
}

// NewEvaluatorCache creates the cache of one evaluator of the AuthConfig identified by owner.
func NewEvaluatorCache(keyTemplate expressions.Value, ttl int, owner types.NamespacedName) EvaluatorCache {
	capacity := EvaluatorCacheSize * 1024 * 1024
	c := &evaluatorCache{
		keyTemplate:  keyTemplate,
		ttl:          ttl,
		owner:        owner.String(),
		metricLabels: map[string]string{"namespace": owner.Namespace, "authconfig": owner.Name},
		maxEntrySize: maxEntrySize(capacity),
		sizeInMB:     EvaluatorCacheSize,
	}
	// freecache keeps entries with a TTL <= 0 forever, and preallocates its whole capacity
	if ttl > 0 {
		c.store = gocache.New(cache_store.NewFreecache(freecache.NewCache(capacity), &cache_store.Options{Expiration: time.Duration(ttl) * time.Second}))
	}
	return c
}

// maxEntrySize mirrors the admission check of freecache (segment.go): key plus value must fit in a quarter of a segment, minus the entry header.
func maxEntrySize(capacity int) int {
	return max(capacity, freecacheMinCapacity)/freecacheSegments/4 - freecache.ENTRY_HDR_SIZE
}

// evaluatorCache caches JSON values (objects, arrays, strings, etc).
// Each failure kind is logged at the default level once per cache instance, i.e. once per evaluator per reconciliation of the AuthConfig,
// and never with the cache key, which may hold a credential, or with other request data.
type evaluatorCache struct {
	keyTemplate  expressions.Value
	ttl          int
	store        *gocache.Cache // nil when ttl <= 0
	owner        string
	metricLabels map[string]string
	maxEntrySize int
	sizeInMB     int

	disabledLogged      atomic.Bool
	keyUnresolvedLogged atomic.Bool
	entryTooLargeLogged atomic.Bool
	storeFailedLogged   atomic.Bool
}

func (c *evaluatorCache) Call(ctx context.Context, pipeline auth.AuthPipeline, config metrics.Object, evaluator auth.AuthConfigEvaluator) (any, error) {
	logger := log.FromContext(ctx)

	if c.store == nil {
		if c.disabledLogged.CompareAndSwap(false, true) {
			logger.Info("evaluator cache ttl is not positive, not cached", "authconfig", c.owner, "evaluator", config.GetName(), "ttl", c.ttl)
		}
		return evaluator.Call(pipeline, ctx)
	}

	authJSON := pipeline.GetAuthorizationJSON()
	resolvedKey, err := c.keyTemplate.ResolveFor(authJSON)
	if err != nil || resolvedKey == nil {
		metrics.ReportMetricWithObject(authServerEvaluatorCacheKeyUnresolvedMetric, config, c.metricLabels)
		if c.keyUnresolvedLogged.CompareAndSwap(false, true) {
			logger.Info("evaluator cache key did not resolve, not cached", c.keyUnresolvedDetails(config, err)...)
		}
		if err != nil && logger.V(1).Enabled() {
			// CEL runtime errors can quote values from the request (e.g. "no such key: <header value>"), so the error
			// logged is the one of resolving the key over the Authorization JSON with every string and number replaced
			logger.V(1).Info("evaluator cache key did not resolve", "err", c.redactedResolveError(authJSON))
		}
		return evaluator.Call(pipeline, ctx)
	}

	key := resolvedKey

	if cachedObj, err := c.get(key); err != nil {
		logger.V(1).Info("failed to retrieve data from the cache", "err", err)
	} else if cachedObj != nil {
		metrics.ReportMetricWithObject(authServerEvaluatorCacheHitMetric, config, c.metricLabels)
		return cachedObj, nil
	}
	metrics.ReportMetricWithObject(authServerEvaluatorCacheMissMetric, config, c.metricLabels)

	obj, err := evaluator.Call(pipeline, ctx)
	if err != nil {
		return obj, err
	}

	if err := c.set(key, obj); err != nil {
		metrics.ReportMetricWithObject(authServerEvaluatorCacheStoreFailedMetric, config, c.metricLabels)
		logger.V(1).Info("unable to store data in the cache", "err", err)

		if tooLarge, ok := errors.AsType[*cacheEntryTooLargeError](err); ok {
			if c.entryTooLargeLogged.CompareAndSwap(false, true) {
				logger.Info("evaluator cache entry too large, not cached", "authconfig", c.owner, "evaluator", config.GetName(), "entrySize", tooLarge.size, "limit", tooLarge.limit, "evaluatorCacheSize", c.sizeInMB)
			}
		} else if c.storeFailedLogged.CompareAndSwap(false, true) {
			logger.Info("evaluator cache failed to store entry, not cached", "authconfig", c.owner, "evaluator", config.GetName(), "reason", storeFailureReason(err))
		}
	}

	return obj, nil
}

func (c *evaluatorCache) Shutdown() error {
	if c.store != nil {
		return c.store.Clear()
	}
	return nil
}

func (c *evaluatorCache) keyUnresolvedDetails(config metrics.Object, err error) []any {
	details := []any{"authconfig", c.owner, "evaluator", config.GetName()}
	switch c.keyTemplate.(type) {
	case *cel.Expression:
		details = append(details, "keySource", "expression")
	case *json.JSONValue:
		details = append(details, "keySource", "selector", "hint", "cache.key.selector is a JSON path or template; a CEL expression goes under cache.key.expression")
	}
	if err != nil {
		details = append(details, "reason", "error")
	} else {
		details = append(details, "reason", "null")
	}
	return details
}

// redactedResolveError resolves the key again over the Authorization JSON with every string and number replaced, at any
// depth, so that the error can quote the expression and field names but no value from the request. A replacement keeps
// the type of the value, so the key fails to resolve the same way unless the failure depends on the value. Object member
// names stay, as paths need them to resolve the same way, so a key that turns member names into values can still quote
// them.
// log.RedactedAuthorizationJSON would not do: it only redacts fields and headers known to be sensitive, and not inside
// arrays.
func (c *evaluatorCache) redactedResolveError(authJSON string) string {
	decoder := gojson.NewDecoder(strings.NewReader(authJSON))
	decoder.UseNumber()
	var data any
	if err := decoder.Decode(&data); err != nil {
		return "unavailable"
	}
	redacted, err := gojson.Marshal(redactValues(data))
	if err != nil {
		return "unavailable"
	}
	if _, err := c.keyTemplate.ResolveFor(string(redacted)); err != nil {
		return err.Error()
	}
	return "unavailable"
}

// redactValues replaces, in place, every string and number in a JSON value decoded with UseNumber, including object
// members and array items. Booleans stay, as they can't hold a credential.
func redactValues(value any) any {
	switch v := value.(type) {
	case string:
		return "***REDACTED***"
	case gojson.Number:
		return gojson.Number("0")
	case []any:
		for i := range v {
			v[i] = redactValues(v[i])
		}
	case map[string]any:
		for k := range v {
			v[k] = redactValues(v[k])
		}
	}
	return value
}

// get returns nil for a missing entry, which gocache's freecache store reports as an error. It returns no other error
// for a string key, and gocache turns every key into a string.
func (c *evaluatorCache) get(key any) (any, error) {
	valueAsBytes, err := c.store.Get(key)
	if err != nil {
		return nil, nil
	}
	var value any
	if err := gojson.Unmarshal(valueAsBytes.([]byte), &value); err != nil {
		return nil, err
	}
	return value, nil
}

// set returns errors that never include the key. gocache's freecache store quotes the key in its errors and drops
// the error types of freecache, so set checks the sizes freecache would reject before the entry reaches gocache.
func (c *evaluatorCache) set(key any, value any) error {
	valueAsBytes, err := gojson.Marshal(value)
	if err != nil {
		return &cacheValueEncodingError{err: err}
	}
	keySize := storedKeySize(key)
	if keySize > freecacheMaxKeySize {
		return errCacheKeyTooLarge
	}
	if size := keySize + len(valueAsBytes); size > c.maxEntrySize {
		return &cacheEntryTooLargeError{size: size, limit: c.maxEntrySize}
	}
	if err := c.store.Set(key, valueAsBytes, nil); err != nil {
		return errCacheStoreFailed
	}
	return nil
}

// storedKeySize is the size of the key as gocache passes it to freecache.
func storedKeySize(key any) int {
	if s, ok := key.(string); ok {
		return len(s)
	}
	return gocacheHashedKeySize
}

var (
	errCacheKeyTooLarge = errors.New("cache key larger than 65535 bytes")
	errCacheStoreFailed = errors.New("cache store failed")
)

// storeFailureReason describes a failure to store an entry with a fixed text, because encoding errors can quote the value.
func storeFailureReason(err error) string {
	if errors.Is(err, errCacheKeyTooLarge) {
		return errCacheKeyTooLarge.Error()
	}
	if _, ok := errors.AsType[*cacheValueEncodingError](err); ok {
		return "evaluated object cannot be encoded as JSON"
	}
	return "unknown"
}

type cacheEntryTooLargeError struct {
	size, limit int
}

func (e *cacheEntryTooLargeError) Error() string {
	return fmt.Sprintf("cache entry of %d bytes is larger than the limit of %d bytes", e.size, e.limit)
}

type cacheValueEncodingError struct {
	err error
}

func (e *cacheValueEncodingError) Error() string {
	return "cannot encode the evaluated object as JSON: " + e.err.Error()
}

func (e *cacheValueEncodingError) Unwrap() error {
	return e.err
}
