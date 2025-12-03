package utils

import (
	"os"
	"reflect"
	"strconv"
)

type envVar interface {
	string | int | int64 | bool | float32 | float64
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
			return any(v).(T)
		case reflect.Float64:
			v, _ := strconv.ParseFloat(val, 64)
			return any(v).(T)
		}
		return any(nil).(T)
	}
}
