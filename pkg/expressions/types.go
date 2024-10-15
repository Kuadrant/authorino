package expressions

type Value interface {
	ResolveFor(jsonData string) (interface{}, error)
}
