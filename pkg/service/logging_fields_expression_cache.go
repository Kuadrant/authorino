package service

import "github.com/kuadrant/authorino/pkg/expressions/cel"

const loggingFieldExpressionCacheCapacity = 256

var loggingFieldExpressions = cel.NewExpressionCache(loggingFieldExpressionCacheCapacity)
