package utils

import (
	"os"
	"testing"

	"gotest.tools/assert"
)

func TestFetchEnvVarString(t *testing.T) {
	_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "val")
	defer func() {
		_ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR")
	}()

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", "def"), "val")
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", "def"), "def")
}

func TestFetchEnvVarInt(t *testing.T) {
	_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "123")
	defer func() {
		_ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR")
	}()

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", 456), 123)
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", 456), 456)
}

func TestFetchEnvVarInt64(t *testing.T) {
	_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "123")
	defer func() {
		_ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR")
	}()

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", int64(456)), int64(123))
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", int64(456)), int64(456))
}

func TestFetchEnvVarBool(t *testing.T) {
	_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "true")
	defer func() {
		_ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR")
	}()

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", false), true)
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", false), false)
}

func TestFetchEnvVarFloat32(t *testing.T) {
	_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "3.14")
	defer func() {
		_ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR")
	}()

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", float32(0)), float32(3.14))
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", float32(1.5)), float32(1.5))
}

func TestFetchEnvVarFloat64(t *testing.T) {
	_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "3.14")
	defer func() {
		_ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR")
	}()

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", float64(0)), float64(3.14))
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", float64(1.5)), float64(1.5))
}

func TestEnvVarStringSlice(t *testing.T) {
	t.Run("unset returns nil", func(t *testing.T) {
		result := EnvVarStringSlice("AUTHORINO_TEST_UNSET_VAR", ",")
		assert.Assert(t, result == nil)
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "")
		defer func() { _ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR") }()
		result := EnvVarStringSlice("AUTHORINO_TEST_ENV_VAR", ",")
		assert.Assert(t, result == nil)
	})

	t.Run("single value", func(t *testing.T) {
		_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "foo")
		defer func() { _ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR") }()
		result := EnvVarStringSlice("AUTHORINO_TEST_ENV_VAR", ",")
		assert.Equal(t, len(result), 1)
		assert.Equal(t, result[0], "foo")
	})

	t.Run("multiple values", func(t *testing.T) {
		_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "foo,bar,baz")
		defer func() { _ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR") }()
		result := EnvVarStringSlice("AUTHORINO_TEST_ENV_VAR", ",")
		assert.Equal(t, len(result), 3)
		assert.Equal(t, result[0], "foo")
		assert.Equal(t, result[1], "bar")
		assert.Equal(t, result[2], "baz")
	})

	t.Run("trims whitespace", func(t *testing.T) {
		_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", " foo , bar ")
		defer func() { _ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR") }()
		result := EnvVarStringSlice("AUTHORINO_TEST_ENV_VAR", ",")
		assert.Equal(t, len(result), 2)
		assert.Equal(t, result[0], "foo")
		assert.Equal(t, result[1], "bar")
	})

	t.Run("skips empty entries", func(t *testing.T) {
		_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "foo,,bar,")
		defer func() { _ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR") }()
		result := EnvVarStringSlice("AUTHORINO_TEST_ENV_VAR", ",")
		assert.Equal(t, len(result), 2)
		assert.Equal(t, result[0], "foo")
		assert.Equal(t, result[1], "bar")
	})

	t.Run("custom separator", func(t *testing.T) {
		_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "foo:bar:baz")
		defer func() { _ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR") }()
		result := EnvVarStringSlice("AUTHORINO_TEST_ENV_VAR", ":")
		assert.Equal(t, len(result), 3)
		assert.Equal(t, result[0], "foo")
		assert.Equal(t, result[1], "bar")
		assert.Equal(t, result[2], "baz")
	})
}

func TestFetchEnvVarInvalid(t *testing.T) {
	_ = os.Setenv("AUTHORINO_TEST_ENV_VAR", "NaN")
	defer func() {
		_ = os.Unsetenv("AUTHORINO_TEST_ENV_VAR")
	}()

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", 456), 0)
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", 456), 456)
}
