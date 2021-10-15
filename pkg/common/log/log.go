package log

import (
	"strings"

	"github.com/go-logr/logr"
	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	// For mocking the default logger in the tests
	Logger logr.Logger = ctrl.Log

	// Level holds the minimum level of messages that should be logged.
	// It is useful for checking the log level in the code and thus avoid expensive
	// tasks only required for some specific levels.
	// Level is setup by the `Setup` function.
	Level LogLevel
)

type LogLevel zapcore.Level

func (l *LogLevel) Debug() bool {
	return *l == LogLevel(zapcore.DebugLevel)
}

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

// Setup sets up a logger with the given level and output mode.
func Setup(level LogLevel, mode LogMode) logr.Logger {
	logger := NewLogger(level, mode)

	ctrl.SetLogger(logger) // fulfills `logger` as the de facto logger used by controller-runtime
	klog.SetLogger(logger)
	Level = level

	Logger.Info("setting instance base logger", "min level", level.String(), "mode", mode.String())

	return logger
}

// NewLogger returns a new logger with the given level and output mode.
func NewLogger(level LogLevel, mode LogMode) logr.Logger {
	return zap.New(
		zap.Level(zapcore.Level(level)),
		zap.UseDevMode(mode == LogModeDev),
	)
}

// WithName adds a new element to the logger's name.
// Successive calls with WithName continue to append
// suffixes to the logger's name.  It's strongly recommended
// that name segments contain only letters, digits, and hyphens
// (see the github.com/go-logr/logr package documentation for more information).
func WithName(name string) logr.Logger {
	return Logger.WithName(name)
}

// WithValues adds some key-value pairs of context to a logger.
// See Info for documentation on how key/value pairs work.
func WithValues(keysAndValues ...interface{}) logr.Logger {
	return Logger.WithValues(keysAndValues...)
}
