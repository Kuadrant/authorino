package log

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	// Log is a singleton base logger that can be used across the system,
	// either directly or to create other loggers with name, with values,
	// and/or locked to a given log level.
	// It is initialized to the promise delegation log provided by
	// sigs.k8s.io/controller-runtime, which points to a no-op (null) logger
	// until `SetLogger` is called.
	// This is also useful for mocking the default logger tests.
	Log logr.Logger = ctrl.Log
)

type Logger = logr.Logger

type LogLevel zapcore.Level

func (l *LogLevel) String() string {
	return zapcore.Level(*l).String()
}

// ToLogLevel converts a string to a log level.
func ToLogLevel(level string) LogLevel {
	var l zapcore.Level
	_ = l.UnmarshalText([]byte(level))
	return LogLevel(l)
}

// LogMode defines the log output mode.
type LogMode int8

const (
	// LogModeProd is the log mode for production.
	LogModeProd LogMode = iota
	// LogModeDev is for more human-readable outputs, extra stack traces
	// and logging info. (aka Zap's "development config".)
	LogModeDev
)

func (f *LogMode) String() string {
	switch *f {
	case LogModeProd:
		return "production"
	case LogModeDev:
		return "development"
	default:
		return "unknown"
	}
}

// ToLogMode converts a string to a log mode.
// Use either 'production' for `LogModeProd` or 'development' for `LogModeDev`.
func ToLogMode(mode string) LogMode {
	switch strings.ToLower(mode) {
	case "production":
		return LogModeProd
	case "development":
		return LogModeDev
	default:
		panic("unknown log mode")
	}
}

// Options is a set of options for a configured logger.
type Options struct {
	Level LogLevel
	Mode  LogMode
}

// SetLogger sets up a logger.
func SetLogger(logger logr.Logger) {
	opts := extractOptions(logger)

	Log = logger

	ctrl.SetLogger(logger) // fulfills `logger` as the de facto logger used by controller-runtime
	klog.SetLogger(logger)

	logger.Info("setting instance base logger", "min level", opts.Level.String(), "mode", opts.Mode.String())
}

// WithName uses the singleton logger to create a new logger with the given name.
func WithName(name string) logr.Logger {
	return Log.WithName(name)
}

// WithName uses the singleton logger to create a new logger with the given values.
func WithValues(keysAndValues ...interface{}) logr.Logger {
	return Log.WithValues(keysAndValues...)
}

// V uses the singleton logger to create a new logger for the given log level.
func V(level int) logr.Logger {
	return Log.V(level)
}

// IntoContext takes a context and sets the logger as one of its values.
// Use FromContext function to retrieve the logger.
func IntoContext(ctx context.Context, log logr.Logger) context.Context {
	return logr.NewContext(ctx, log)
}

// FromContext returns a logger with predefined values from a context.Context.
func FromContext(ctx context.Context, keysAndValues ...interface{}) logr.Logger {
	var log logr.Logger = Log
	if ctx != nil {
		if logger := logr.FromContext(ctx); logger != nil {
			log = logger
		}
	}
	return log.WithValues(keysAndValues...)
}

// NewLogger returns a new logger with the given options.
// `logger` param is the actual logger implementation; when omitted, a new
// logger based on sigs.k8s.io/controller-runtime/pkg/log/zap is created.
func NewLogger(opts Options, logger logr.Logger) logr.Logger {
	l := &configuredLogger{Options: opts}

	if logger != nil {
		l.Logger = logger
	} else {
		l.Logger = zap.New(
			zap.Level(zapcore.Level(opts.Level)),
			zap.UseDevMode(opts.Mode == LogModeDev),
		)
	}

	return l
}

// configuredLogger is a delegation logger that holds information about the log options.
type configuredLogger struct {
	Options Options
	Logger  logr.Logger
}

func (l *configuredLogger) Enabled() bool {
	return l.Logger.Enabled()
}

func (l *configuredLogger) Info(msg string, keysAndValues ...interface{}) {
	l.Logger.Info(msg, keysAndValues...)
}

func (l *configuredLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	l.Logger.Error(err, msg, keysAndValues...)
}

func (l *configuredLogger) V(level int) logr.Logger {
	return NewLogger(l.Options, l.Logger.V(level))
}

func (l *configuredLogger) WithValues(keysAndValues ...interface{}) logr.Logger {
	return NewLogger(l.Options, l.Logger.WithValues(keysAndValues...))
}

func (l *configuredLogger) WithName(name string) logr.Logger {
	return NewLogger(l.Options, l.Logger.WithName(name))
}

func extractOptions(l logr.Logger) Options {
	if cl, ok := l.(*configuredLogger); ok {
		return cl.Options
	} else {
		return Options{
			Level: LogLevel(zapcore.InfoLevel),
			Mode:  LogModeProd,
		}
	}
}
