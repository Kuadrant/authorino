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

func TestSliceContains(t *testing.T) {
	assert.Check(t, SliceContains([]string{"a", "b", "c"}, "a"))
	assert.Check(t, SliceContains([]string{"a", "b", "c"}, "b"))
	assert.Check(t, SliceContains([]string{"a", "b", "c"}, "c"))
	assert.Check(t, !SliceContains([]string{"a", "b", "c"}, "d"))
	assert.Check(t, SliceContains([]int{1, 2, 3}, 3))
	assert.Check(t, !SliceContains([]int{1, 2, 3}, 4))
}
