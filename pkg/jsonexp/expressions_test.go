package jsonexp

import (
	"testing"

	"gotest.tools/assert"
)

const testJsonData = `{
	"str": "my-value",
	"int": 123,
	"bool": true,
	"obj": {"my-obj-str": "my-obj-value"},
	"arr": ["my-arr-value-1", "my-arr-value-2"]
}`

func TestAnd(t *testing.T) {
	// true && true
	exp := &And{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
		Right: Pattern{
			Selector: "int",
			Operator: EqualOperator,
			Value:    "123",
		},
	}
	ok, err := exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	// false && true
	exp = &And{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
		Right: Pattern{
			Selector: "int",
			Operator: EqualOperator,
			Value:    "123",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)

	// true && false
	exp = &And{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
		Right: Pattern{
			Selector: "int",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)

	// false && false
	exp = &And{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
		Right: Pattern{
			Selector: "int",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}
func TestOneBranchAnd(t *testing.T) {
	// true && nil
	exp := &And{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
	}
	ok, err := exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	// nil && true
	exp = &And{
		Right: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	// false && nil
	exp = &And{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)

	// nil && false
	exp = &And{
		Right: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestEmptyAnd(t *testing.T) {
	// nil && nil
	exp := &And{}
	ok, err := exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)
}

func TestOr(t *testing.T) {
	// true || true
	exp := &Or{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
		Right: Pattern{
			Selector: "int",
			Operator: EqualOperator,
			Value:    "123",
		},
	}
	ok, err := exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	// false || true
	exp = &Or{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
		Right: Pattern{
			Selector: "int",
			Operator: EqualOperator,
			Value:    "123",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	// true || false
	exp = &Or{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
		Right: Pattern{
			Selector: "int",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	// false || false
	exp = &Or{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
		Right: Pattern{
			Selector: "int",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}
func TestOneBranchOr(t *testing.T) {
	// true || nil
	exp := &Or{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
	}
	ok, err := exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	// nil || true
	exp = &Or{
		Right: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	// false || nil
	exp = &Or{
		Left: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)

	// nil || false
	exp = &Or{
		Right: Pattern{
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestEmptyOr(t *testing.T) {
	// nil || nil
	exp := &Or{}
	ok, err := exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestAll(t *testing.T) {
	patterns := []Expression{
		Pattern{ // true
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
		Pattern{ // true
			Selector: "int",
			Operator: EqualOperator,
			Value:    "123",
		},
	}
	ok, err := All(patterns...).Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	patterns = []Expression{
		Pattern{ // true
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
		Pattern{ // false
			Selector: "int",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = All(patterns...).Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestTrivialAll(t *testing.T) {
	patterns := []Expression{
		Pattern{ // true
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
	}
	ok, err := All(patterns...).Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	patterns = []Expression{
		Pattern{ // false
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = All(patterns...).Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestEmptyAll(t *testing.T) {
	ok, err := All().Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)
}

func TestAny(t *testing.T) {
	patterns := []Expression{
		Pattern{ // true
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
		Pattern{ // true
			Selector: "int",
			Operator: EqualOperator,
			Value:    "123",
		},
	}
	ok, err := Any(patterns...).Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	patterns = []Expression{
		Pattern{ // true
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
		Pattern{ // false
			Selector: "int",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = Any(patterns...).Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)
}

func TestTrivialAny(t *testing.T) {
	patterns := []Expression{
		Pattern{ // true
			Selector: "str",
			Operator: EqualOperator,
			Value:    "my-value",
		},
	}
	ok, err := Any(patterns...).Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	patterns = []Expression{
		Pattern{ // false
			Selector: "str",
			Operator: EqualOperator,
			Value:    "wrong-value",
		},
	}
	ok, err = All(patterns...).Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestEmptyAny(t *testing.T) {
	ok, err := Any().Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestAndOr(t *testing.T) {
	exp := All(
		Any(
			Pattern{ // true
				Selector: "str",
				Operator: EqualOperator,
				Value:    "my-value",
			},
			Pattern{ // false
				Selector: "int",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
		),
		Any(
			Pattern{ // false
				Selector: "str",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
			Pattern{ // true
				Selector: "int",
				Operator: EqualOperator,
				Value:    "123",
			},
		),
	)
	ok, err := exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)

	exp = All(
		Any(
			Pattern{ // false
				Selector: "str",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
			Pattern{ // false
				Selector: "int",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
		),
		Any(
			Pattern{ // false
				Selector: "str",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
			Pattern{ // true
				Selector: "int",
				Operator: EqualOperator,
				Value:    "123",
			},
		),
	)
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestOrAnd(t *testing.T) {
	exp := Any(
		All(
			Pattern{ // true
				Selector: "str",
				Operator: EqualOperator,
				Value:    "my-value",
			},
			Pattern{ // false
				Selector: "int",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
		),
		All(
			Pattern{ // false
				Selector: "str",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
			Pattern{ // true
				Selector: "int",
				Operator: EqualOperator,
				Value:    "123",
			},
		),
	)
	ok, err := exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)

	exp = Any(
		All(
			Pattern{ // false
				Selector: "str",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
			Pattern{ // false
				Selector: "int",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
		),
		All(
			Pattern{ // false
				Selector: "str",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
			Pattern{ // true
				Selector: "int",
				Operator: EqualOperator,
				Value:    "123",
			},
		),
	)
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, !ok)

	exp = Any(
		All(
			Pattern{ // true
				Selector: "str",
				Operator: EqualOperator,
				Value:    "my-value",
			},
			Pattern{ // true
				Selector: "int",
				Operator: EqualOperator,
				Value:    "123",
			},
		),
		All(
			Pattern{ // false
				Selector: "str",
				Operator: EqualOperator,
				Value:    "wrong-value",
			},
			Pattern{ // true
				Selector: "int",
				Operator: EqualOperator,
				Value:    "123",
			},
		),
	)
	ok, err = exp.Matches(testJsonData)
	assert.NilError(t, err)
	assert.Check(t, ok)
}
