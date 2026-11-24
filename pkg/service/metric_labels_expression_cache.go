package service

import "github.com/kuadrant/authorino/pkg/expressions/cel"

const metricLabelExpressionCacheCapacity = 256

// sharedMetricLabelExpressions is what NewAuthPipeline hands to every pipeline. Metric labels
// come from the request's filter metadata, not from an AuthConfig, so one cache serves the
// whole process.
var sharedMetricLabelExpressions = cel.NewExpressionCache(metricLabelExpressionCacheCapacity)
