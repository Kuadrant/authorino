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

func TestCopyMap(t *testing.T) {
	m1 := map[string]int{
		"a": 1,
		"b": 2,
	}
	m2 := CopyMap(m1)
	assert.Check(t, &m1 != &m2)
	assert.Equal(t, len(m1), len(m2))
	assert.Equal(t, m1["a"], m2["a"])
	assert.Equal(t, m1["b"], m2["b"])
	m1["a"] = 3
	assert.Check(t, m1["a"] != m2["a"])
}
