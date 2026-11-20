package cel

import (
	"fmt"
	"strings"
	"testing"

	"gotest.tools/assert"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	"go.uber.org/mock/gomock"
)

func TestPredicate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, err := NewPredicate(`auth`)
	assert.ErrorContains(t, err, "wanted bool output type")

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	predicate, err := NewPredicate(`false == true`)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)
	response, err := predicate.Matches(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, response, false)

	predicate, err = NewPredicate(`auth.identity.evil == false`)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)
	response, err = predicate.Matches(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, response, true)

	predicate, err = NewPredicate(`request.http.method == "GET"`)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"request":{"http": {"method": "GET"}}}`)
	response, err = predicate.Matches(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, response, true)

	predicate, err = NewPredicate(`"GET".lowerAscii() == "get"`)
	assert.NilError(t, err)
	response, err = predicate.Matches("{}")
	assert.NilError(t, err)
	assert.Equal(t, response, true)
}

func TestExpression(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)

	expression, err := NewExpression(`auth.identity.evil == false`)
	assert.NilError(t, err)

	v, err := expression.ResolveFor(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, v, true)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)
	expression, err = NewExpression(`auth.?nonexistent.orValue("none")`)
	assert.NilError(t, err)

	v, err = expression.ResolveFor(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, v, "none")
}

func TestMatches(t *testing.T) {
	authJSON := `{"request":{"headers":{"user":"admin"}},"auth":{"identity":{"username":"john","name":"bob","age":42,"pattern":"^j","brokenPattern":"["}}}`

	for _, tc := range []struct {
		name   string
		source string
		want   bool
	}{
		{"literal pattern matches", `auth.identity.username.matches('^jo')`, true},
		{"literal pattern does not match", `auth.identity.username.matches('^x')`, false},
		{"global form", `matches(auth.identity.username, '^jo')`, true},
		{"pattern from input", `auth.identity.username.matches(auth.identity.pattern)`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			predicate, err := NewPredicate(tc.source)
			assert.NilError(t, err)

			got, err := predicate.Matches(authJSON)
			assert.NilError(t, err)
			assert.Equal(t, got, tc.want)
		})
	}

	// The standard overload rejects these receivers; cel-go's stock optimization unwraps optionals
	// and types and matches them.
	for _, tc := range []struct {
		name   string
		source string
		want   string
	}{
		{"optional receiver", `dyn(request.headers.?user).matches('^adm')`, "no such overload: matches"},
		{"optional in a list", `[request.headers.?user, auth.identity.name].exists(h, h.matches('^admin$'))`, "no such overload: matches"},
		{"type receiver", `dyn(type(1)).matches('^int$')`, "no such overload: matches"},
		{"number receiver", `dyn(auth.identity.age).matches('^4')`, "no such overload: matches"},
		{"number in global form", `matches(dyn(auth.identity.age), '^4')`, "no such overload: matches"},
		{"timestamp receiver", `dyn(timestamp('2020-01-01T00:00:00Z')).matches('^2')`, "no such overload"},
		{"duration in global form", `matches(dyn(duration('1s')), '^1')`, "no such overload"},
	} {
		t.Run(tc.name+" fails at evaluation", func(t *testing.T) {
			predicate, err := NewPredicate(tc.source)
			assert.NilError(t, err)

			_, err = predicate.Matches(authJSON)
			assert.Error(t, err, tc.want)
		})
	}

	t.Run("broken literal pattern fails at evaluation", func(t *testing.T) {
		predicate, err := NewPredicate(`auth.identity.username.matches('[')`)
		assert.NilError(t, err)

		_, err = predicate.Matches(authJSON)
		assert.Error(t, err, "error parsing regexp: missing closing ]: `[`")

		// As with the standard overload, the error is absorbed where the other operand decides.
		predicate, err = NewPredicate(`auth.identity.username == 'john' || auth.identity.username.matches('[')`)
		assert.NilError(t, err)

		got, err := predicate.Matches(authJSON)
		assert.NilError(t, err)
		assert.Equal(t, got, true)
	})

	t.Run("broken pattern from input fails at evaluation", func(t *testing.T) {
		predicate, err := NewPredicate(`auth.identity.username.matches(auth.identity.brokenPattern)`)
		assert.NilError(t, err)

		_, err = predicate.Matches(authJSON)
		assert.ErrorContains(t, err, "missing closing ]")
	})
}

// BenchmarkExpressionMatches filters 40 groups with two literal patterns, shaped like a group
// allowlist.
func BenchmarkExpressionMatches(b *testing.B) {
	groups := make([]string, 40)
	for i := range groups {
		groups[i] = fmt.Sprintf(`"tenant-%d:team-%d"`, i, i)
	}
	groups[0] = `"system:authenticated"`
	authJSON := `{"auth":{"identity":{"groups":[` + strings.Join(groups, ",") + `]}}}`

	expression, err := NewExpression(`auth.identity.groups.filter(g, g.matches('^[a-zA-Z0-9][a-zA-Z0-9._:-]*$') && !g.matches('^system:'))`)
	assert.NilError(b, err)

	// The first pattern matches all 40 groups, so the second one runs for every group too.
	got, err := expression.ResolveFor(authJSON)
	assert.NilError(b, err)
	assert.Equal(b, len(got.([]any)), len(groups)-1)

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := expression.Evaluate(authJSON); err != nil {
			b.Fatal(err)
		}
	}
}
