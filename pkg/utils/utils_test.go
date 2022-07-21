package utils

import (
	"strings"
	"testing"

	"gotest.tools/assert"
)

func TestCapitalizeString(t *testing.T) {
	assert.Equal(t, CapitalizeString(""), "")
	assert.Equal(t, CapitalizeString("a"), "A")
	assert.Equal(t, CapitalizeString("abc"), "Abc")
	assert.Equal(t, CapitalizeString("Abc"), "Abc")
}

func TestSubtractSlice(t *testing.T) {
	assert.Equal(t, strings.Join(SubtractSlice([]string{"a", "b", "c"}, []string{"b", "c"}), ""), "a")
	assert.Equal(t, strings.Join(SubtractSlice([]string{}, []string{"b", "c"}), ""), "")
	assert.Equal(t, strings.Join(SubtractSlice([]string{"a", "b", "c"}, []string{"c", "d"}), ""), "ab")
	assert.Equal(t, strings.Join(SubtractSlice([]string{"a", "b", "c"}, []string{}), ""), "abc")
}
