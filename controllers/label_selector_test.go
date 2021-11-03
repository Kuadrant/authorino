package controllers

import (
	"testing"

	mock_controllers "github.com/kuadrant/authorino/controllers/mocks"
	mock_client "github.com/kuadrant/authorino/controllers/mocks/controller-runtime/client"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func TestWatched(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	object := mock_controllers.NewMockWatchedObject(mockController)

	object.EXPECT().GetLabels().Return(map[string]string{
		"audience": "echo-api",
		"group":    "pro-users",
	}).Times(7)

	// no selectors
	assert.Check(t, Watched(object, ToLabelSelector("")))

	// selector matches
	assert.Check(t, Watched(object, ToLabelSelector("audience=echo-api")))
	assert.Check(t, Watched(object, ToLabelSelector("group=pro-users")))
	assert.Check(t, Watched(object, ToLabelSelector("audience=echo-api,group=pro-users")))
	assert.Check(t, Watched(object, ToLabelSelector("audience in (echo-api,other")))

	// selector doesn't match
	assert.Check(t, !Watched(object, ToLabelSelector("audience=other")))
	assert.Check(t, !Watched(object, ToLabelSelector("! audience")))
}

func TestLabelSelectorPredicate(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	object := mock_client.NewMockObject(mockController)

	var f predicate.Funcs

	// no selectors
	f = LabelSelectorPredicate(ToLabelSelector(""))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.CreateFunc(event.CreateEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.UpdateFunc(event.UpdateEvent{ObjectNew: object, ObjectOld: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.DeleteFunc(event.DeleteEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.GenericFunc(event.GenericEvent{Object: object}))

	// no selectors
	f = LabelSelectorPredicate(ToLabelSelector("expected-label=expected-value"))
	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, !f.CreateFunc(event.CreateEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{}).Times(2)
	assert.Check(t, !f.UpdateFunc(event.UpdateEvent{ObjectNew: object, ObjectOld: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, !f.DeleteFunc(event.DeleteEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, !f.GenericFunc(event.GenericEvent{Object: object}))
}

func TestToLabelSelector(t *testing.T) {
	var selector labels.Selector
	var reqs labels.Requirements

	selector = ToLabelSelector("")
	reqs, _ = selector.Requirements()
	assert.Equal(t, len(reqs), 0)
	assert.Check(t, selector.Matches(labels.Set{}))
	assert.Check(t, selector.Matches(labels.Set{"authorino.3scale.net/managed-by": "authorino"}))

	selector = ToLabelSelector("authorino.3scale.net/managed-by=authorino")
	reqs, _ = selector.Requirements()
	assert.Equal(t, len(reqs), 1)
	assert.Check(t, selector.Matches(labels.Set{"authorino.3scale.net/managed-by": "authorino"}))

	selector = ToLabelSelector("authorino.3scale.net/managed-by!=authorino")
	reqs, _ = selector.Requirements()
	assert.Equal(t, len(reqs), 1)
	assert.Check(t, !selector.Matches(labels.Set{"authorino.3scale.net/managed-by": "authorino"}))

	selector = ToLabelSelector("!authorino.3scale.net/managed-by")
	reqs, _ = selector.Requirements()
	assert.Equal(t, len(reqs), 1)
	assert.Check(t, !selector.Matches(labels.Set{"authorino.3scale.net/managed-by": "authorino"}))

	selector = ToLabelSelector("authorino.3scale.net/managed-by=authorino,other-label=other-value")
	reqs, _ = selector.Requirements()
	assert.Equal(t, len(reqs), 2)
	assert.Check(t, selector.Matches(labels.Set{
		"authorino.3scale.net/managed-by": "authorino",
		"other-label":                     "other-value",
	}))

	selector = ToLabelSelector("authorino.3scale.net/managed-by in (authorino,kuadrant)")
	reqs, _ = selector.Requirements()
	assert.Equal(t, len(reqs), 1)
	assert.Check(t, selector.Matches(labels.Set{"authorino.3scale.net/managed-by": "authorino"}))
	assert.Check(t, selector.Matches(labels.Set{"authorino.3scale.net/managed-by": "kuadrant"}))

	selector = ToLabelSelector("inval*id-lab?el")
	reqs, _ = selector.Requirements()
	assert.Equal(t, len(reqs), 0)
}
