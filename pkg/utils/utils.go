/*
Use this package with care.
Do not add here anything that deserves a package of its own, like complex types, structs and interfaces.
*/

package utils

import "unicode"

func CapitalizeString(s string) string {
	if len(s) == 0 {
		return ""
	}
	r := []rune(s)
	return string(append([]rune{unicode.ToUpper(r[0])}, r[1:]...))
}

func SubtractSlice(sl1, sl2 []string) []string {
	type obj struct{}
	m := make(map[string]obj)
	for _, s := range sl2 {
		m[s] = obj{}
	}
	diff := []string{}
	for _, v := range sl1 {
		if _, remove := m[v]; remove {
			continue
		}
		diff = append(diff, v)
	}
	return diff
}

func SliceContains[T comparable](s []T, val T) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}

func CopyMap[T comparable, U any](m map[T]U) map[T]U {
	m2 := make(map[T]U)
	for k, v := range m {
		m2[k] = v
	}
	return m2
}
