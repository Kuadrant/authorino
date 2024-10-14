package expressions

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func CelCompile(expression string, opts ...cel.EnvOption) (cel.Program, error) {
	env, env_err := cel.NewEnv(opts...)
	if env_err != nil {
		return nil, env_err
	}

	ast, issues := env.Parse(expression)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	checked, issues := env.Check(ast)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	program, err := env.Program(checked)
	if err != nil {
		return nil, err
	}
	return program, nil
}

func CelValueToJSON(val ref.Val) (string, error) {
	v, err := val.ConvertToNative(reflect.TypeOf(&structpb.Value{}))
	if err != nil {
		return "", err
	}
	marshaller := protojson.MarshalOptions{Multiline: false}
	bytes, err := marshaller.Marshal(v.(proto.Message))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
