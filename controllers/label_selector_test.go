package controllers

import (
	"testing"

	mock_controllers "github.com/kuadrant/authorino/controllers/mocks"
	mock_client "github.com/kuadrant/authorino/controllers/mocks/controller-runtime/client"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
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
	}).Times(5)

	// no selectors
	assert.Check(t, Watched(object, map[string]string{}))

	// aselector matches
	assert.Check(t, Watched(object, map[string]string{"audience": "echo-api"}))
	assert.Check(t, Watched(object, map[string]string{"group": "pro-users"}))
	assert.Check(t, Watched(object, map[string]string{"audience": "echo-api", "group": "pro-users"}))

	// selector doesn't match
	assert.Check(t, !Watched(object, map[string]string{"other-expected-label": "something"}))
}

func TestFilterByLabels(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	object := mock_client.NewMockObject(mockController)

	var f predicate.Funcs

	// no selectors
	f = FilterByLabels(map[string]string{})

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.CreateFunc(event.CreateEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.UpdateFunc(event.UpdateEvent{ObjectNew: object, ObjectOld: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.DeleteFunc(event.DeleteEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.GenericFunc(event.GenericEvent{Object: object}))

	// no selectors
	f = FilterByLabels(map[string]string{"extected-label": "some-value"})
	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, !f.CreateFunc(event.CreateEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{}).Times(2)
	assert.Check(t, !f.UpdateFunc(event.UpdateEvent{ObjectNew: object, ObjectOld: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, !f.DeleteFunc(event.DeleteEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, !f.GenericFunc(event.GenericEvent{Object: object}))
}

func TestToLabelSelectors(t *testing.T) {
	var selectors map[string]string

	selectors = ToLabelSelectors("")
	assert.Equal(t, len(selectors), 0)

	selectors = ToLabelSelectors("authorino.3scale.net/managed-by=authorino")
	assert.Equal(t, len(selectors), 1)
	assert.Equal(t, selectors["authorino.3scale.net/managed-by"], "authorino")

	selectors = ToLabelSelectors("authorino.3scale.net/managed-by=authorino other-label=other-value")
	assert.Equal(t, len(selectors), 2)
	assert.Equal(t, selectors["authorino.3scale.net/managed-by"], "authorino")
	assert.Equal(t, selectors["other-label"], "other-value")

	selectors = ToLabelSelectors(`value-with-quotes="my value"`)
	assert.Equal(t, len(selectors), 1)
	assert.Equal(t, selectors["value-with-quotes"], "my value")

	selectors = ToLabelSelectors("label1=value1\tlabel2=value2")
	assert.Equal(t, len(selectors), 2)
	assert.Equal(t, selectors["label1"], "value1")
	assert.Equal(t, selectors["label2"], "value2")

	selectors = ToLabelSelectors("invalid-label")
	assert.Equal(t, len(selectors), 0)
	val, found := selectors["invalid-label"]
	assert.Equal(t, val, "")
	assert.Check(t, !found)
}
