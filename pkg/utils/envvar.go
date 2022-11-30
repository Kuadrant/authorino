package utils

import (
	"os"
	"reflect"
	"strconv"
)

type envVar interface {
	string | int | int64 | bool
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
		}
		return any(nil).(T)
	}
}
