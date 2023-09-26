package jsonexp

import (
	"fmt"
	"regexp"

	"github.com/tidwall/gjson"
)

type Operator int8

const (
	UnknownOperator Operator = iota
	EqualOperator
	NotEqualOperator
	IncludesOperator
	ExcludesOperator
	RegexOperator
)

func (o *Operator) String() string {
	switch *o {
	case EqualOperator:
		return "eq"
	case NotEqualOperator:
		return "neq"
	case IncludesOperator:
		return "incl"
	case ExcludesOperator:
		return "excl"
	case RegexOperator:
		return "matches"
	}
	return "unknown"
}

func OperatorFromString(operator string) Operator {
	switch operator {
	case "eq":
		return EqualOperator
	case "neq":
		return NotEqualOperator
	case "incl":
		return IncludesOperator
	case "excl":
		return ExcludesOperator
	case "matches":
		return RegexOperator
	}
	return UnknownOperator
}

type Pattern struct {
	Selector string
	Operator Operator
	Value    string
}

func (p Pattern) Matches(json string) (bool, error) {
	expectedValue := p.Value
	obtainedValue := gjson.Get(json, p.Selector)

	switch p.Operator {
	case EqualOperator:
		return (expectedValue == obtainedValue.String()), nil

	case NotEqualOperator:
		return (expectedValue != obtainedValue.String()), nil

	case IncludesOperator:
		for _, item := range obtainedValue.Array() {
			if expectedValue == item.String() {
				return true, nil
			}
		}
		return false, nil

	case ExcludesOperator:
		for _, item := range obtainedValue.Array() {
			if expectedValue == item.String() {
				return false, nil
			}
		}
		return true, nil

	case RegexOperator:
		re, err := regexp.Compile(expectedValue)
		if err != nil {
			return false, err
		}
		return re.MatchString(obtainedValue.String()), nil

	default:
		return false, fmt.Errorf("unsupported operator for json authorization")
	}
}

func (p Pattern) String() string {
	return fmt.Sprintf("%s %s %s", p.Selector, p.Operator.String(), p.Value)
}

type Expression interface {
	Matches(json string) (bool, error)
}

type And struct {
	Left  Expression
	Right Expression
}

func (a *And) Matches(json string) (bool, error) {
	if a.Left != nil {
		left, err := a.Left.Matches(json)
		if err != nil || !left {
			return false, err
		}
	}
	if a.Right != nil {
		right, err := a.Right.Matches(json)
		if err != nil || !right {
			return false, err
		}
	}
	return true, nil
}

func (a *And) String() string {
	return fmt.Sprintf("(%s && %s)", a.Left, a.Right)
}

type Or struct {
	Left  Expression
	Right Expression
}

func (o *Or) Matches(json string) (bool, error) {
	if o.Left != nil {
		left, err := o.Left.Matches(json)
		if err != nil {
			return false, err
		}
		if left {
			return true, nil
		}
	}
	if o.Right != nil {
		right, err := o.Right.Matches(json)
		if err != nil {
			return false, err
		}
		return right, nil
	}
	return false, nil
}

func (o *Or) String() string {
	return fmt.Sprintf("(%s || %s)", o.Left, o.Right)
}

func All(expressions ...Expression) Expression {
	if len(expressions) == 0 {
		return &And{}
	}
	return &And{
		Left:  expressions[0],
		Right: All(expressions[1:]...),
	}
}

func Any(expressions ...Expression) Expression {
	if len(expressions) == 0 {
		return &Or{}
	}
	return &Or{
		Left:  expressions[0],
		Right: Any(expressions[1:]...),
	}
}
