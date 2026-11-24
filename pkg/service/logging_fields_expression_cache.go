package service

import "github.com/kuadrant/authorino/pkg/expressions/cel"

const loggingFieldExpressionCacheCapacity = 256

// sharedLoggingFieldExpressions is what NewAuthPipeline hands to every pipeline. Logging
// fields come from the request's filter metadata, not from an AuthConfig, so one cache
// serves the whole process.
var sharedLoggingFieldExpressions = cel.NewExpressionCache(loggingFieldExpressionCacheCapacity)
