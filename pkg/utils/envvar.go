package utils

import (
	"os"
	"reflect"
	"strconv"
	"strings"
)

type envVar interface {
	string | int | int64 | bool | float32 | float64
}

func EnvVarStringSlice(key, sep string) []string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	parts := strings.Split(val, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			result = append(result, s)
		}
	}
	return result
}

func EnvVar[T envVar](key string, def T) T {
	val, ok := os.LookupEnv(key)
	if !ok {
		return def
	} else {
		switch reflect.ValueOf(def).Kind() {
		case reflect.String:
			return any(val).(T)
		case reflect.Int:
			v, _ := strconv.Atoi(val)
			return any(v).(T)
		case reflect.Int64:
			v, _ := strconv.ParseInt(val, 10, 64)
			return any(v).(T)
		case reflect.Bool:
			v, _ := strconv.ParseBool(val)
			return any(v).(T)
		case reflect.Float32:
			v, _ := strconv.ParseFloat(val, 32)
			return any(float32(v)).(T)
		case reflect.Float64:
			v, _ := strconv.ParseFloat(val, 64)
			return any(v).(T)
		}
		return any(nil).(T)
	}
}
