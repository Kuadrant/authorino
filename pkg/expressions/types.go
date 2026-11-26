package expressions

type Value interface {
	ResolveFor(jsonData string) (interface{}, error)
}

// Lookup is implemented by a Value that can tell a source that selects nothing from one that selects null or an empty
// value.
type Lookup interface {
	// LookupFor returns what the sources of the value select in the JSON data: the value of a path, or the values of the
	// placeholders of a template, in order and without its static text. found is false when a path or a placeholder
	// selects nothing, or a placeholder names no path or is left open.
	LookupFor(jsonData string) (value any, found bool)
}
