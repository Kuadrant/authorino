package utils

import (
	"os"
	"testing"

	"gotest.tools/assert"
)

func TestFetchEnvVarString(t *testing.T) {
	os.Setenv("AUTHORINO_TEST_ENV_VAR", "val")
	defer os.Unsetenv("AUTHORINO_TEST_ENV_VAR")

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", "def"), "val")
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", "def"), "def")
}

func TestFetchEnvVarInt(t *testing.T) {
	os.Setenv("AUTHORINO_TEST_ENV_VAR", "123")
	defer os.Unsetenv("AUTHORINO_TEST_ENV_VAR")

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", 456), 123)
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", 456), 456)
}

func TestFetchEnvVarInt64(t *testing.T) {
	os.Setenv("AUTHORINO_TEST_ENV_VAR", "123")
	defer os.Unsetenv("AUTHORINO_TEST_ENV_VAR")

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", int64(456)), int64(123))
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", int64(456)), int64(456))
}

func TestFetchEnvVarBool(t *testing.T) {
	os.Setenv("AUTHORINO_TEST_ENV_VAR", "true")
	defer os.Unsetenv("AUTHORINO_TEST_ENV_VAR")

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", false), true)
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", false), false)
}

func TestFetchEnvVarInvalid(t *testing.T) {
	os.Setenv("AUTHORINO_TEST_ENV_VAR", "NaN")
	defer os.Unsetenv("AUTHORINO_TEST_ENV_VAR")

	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR", 456), 0)
	assert.Equal(t, EnvVar("AUTHORINO_TEST_ENV_VAR_OTHER", 456), 456)
}
