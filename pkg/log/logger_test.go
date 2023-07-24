package log

import (
	"testing"

	"gotest.tools/assert"
)

func TestLogLevelToString(t *testing.T) {
	level := LogLevel(-1)
	assert.Equal(t, level.String(), "debug")

	level = LogLevel(0)
	assert.Equal(t, level.String(), "info")

	level = LogLevel(1)
	assert.Equal(t, level.String(), "warn")

	level = LogLevel(2)
	assert.Equal(t, level.String(), "error")

	level = LogLevel(3)
	assert.Equal(t, level.String(), "dpanic")

	level = LogLevel(4)
	assert.Equal(t, level.String(), "panic")

	level = LogLevel(5)
	assert.Equal(t, level.String(), "fatal")
}

func TestToLogLevel(t *testing.T) {
	assert.Equal(t, int(ToLogLevel("debug")), -1)
	assert.Equal(t, int(ToLogLevel("info")), 0)
	assert.Equal(t, int(ToLogLevel("warn")), 1)
	assert.Equal(t, int(ToLogLevel("error")), 2)
	assert.Equal(t, int(ToLogLevel("dpanic")), 3)
	assert.Equal(t, int(ToLogLevel("panic")), 4)
	assert.Equal(t, int(ToLogLevel("fatal")), 5)
	assert.Equal(t, int(ToLogLevel("invalid")), 0) // falls back to default log level (info) without panicking
}

func TestLogModeToString(t *testing.T) {
	level := LogMode(0)
	assert.Equal(t, level.String(), "production")

	level = LogMode(1)
	assert.Equal(t, level.String(), "development")
}

func TestToLogMode(t *testing.T) {
	assert.Equal(t, int(ToLogMode("production")), 0)
	assert.Equal(t, int(ToLogMode("development")), 1)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf(`ToLogMode("invalid") was expected to panic and it did not.`)
		}
	}()
	_ = ToLogMode("invalid")
}
