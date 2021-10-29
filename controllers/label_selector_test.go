package controllers

import (
	"testing"

	mock_controllers "github.com/kuadrant/authorino/controllers/mocks"
	mock_client "github.com/kuadrant/authorino/controllers/mocks/controller-runtime/client"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	assert.Check(t, Watched(object, metav1.LabelSelector{MatchLabels: map[string]string{}}))

	// aselector matches
	assert.Check(t, Watched(object, metav1.LabelSelector{MatchLabels: map[string]string{"audience": "echo-api"}}))
	assert.Check(t, Watched(object, metav1.LabelSelector{MatchLabels: map[string]string{"group": "pro-users"}}))
	assert.Check(t, Watched(object, metav1.LabelSelector{MatchLabels: map[string]string{"audience": "echo-api", "group": "pro-users"}}))

	// selector doesn't match
	assert.Check(t, !Watched(object, metav1.LabelSelector{MatchLabels: map[string]string{"other-expected-label": "something"}}))
}

func TestLabelSelectorPredicate(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	object := mock_client.NewMockObject(mockController)

	var f predicate.Funcs

	// no selectors
	f = LabelSelectorPredicate(metav1.LabelSelector{MatchLabels: map[string]string{}})

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.CreateFunc(event.CreateEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.UpdateFunc(event.UpdateEvent{ObjectNew: object, ObjectOld: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.DeleteFunc(event.DeleteEvent{Object: object}))

	object.EXPECT().GetLabels().Return(map[string]string{})
	assert.Check(t, f.GenericFunc(event.GenericEvent{Object: object}))

	// no selectors
	f = LabelSelectorPredicate(metav1.LabelSelector{MatchLabels: map[string]string{"extected-label": "some-value"}})
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
	var matchLabels map[string]string

	matchLabels = ToLabelSelector("").MatchLabels
	assert.Equal(t, len(matchLabels), 0)

	matchLabels = ToLabelSelector("authorino.3scale.net/managed-by=authorino").MatchLabels
	assert.Equal(t, len(matchLabels), 1)
	assert.Equal(t, matchLabels["authorino.3scale.net/managed-by"], "authorino")

	matchLabels = ToLabelSelector("authorino.3scale.net/managed-by=authorino other-label=other-value").MatchLabels
	assert.Equal(t, len(matchLabels), 2)
	assert.Equal(t, matchLabels["authorino.3scale.net/managed-by"], "authorino")
	assert.Equal(t, matchLabels["other-label"], "other-value")

	matchLabels = ToLabelSelector(`value-with-quotes="my value"`).MatchLabels
	assert.Equal(t, len(matchLabels), 1)
	assert.Equal(t, matchLabels["value-with-quotes"], "my value")

	matchLabels = ToLabelSelector("label1=value1\tlabel2=value2").MatchLabels
	assert.Equal(t, len(matchLabels), 2)
	assert.Equal(t, matchLabels["label1"], "value1")
	assert.Equal(t, matchLabels["label2"], "value2")

	matchLabels = ToLabelSelector("invalid-label").MatchLabels
	assert.Equal(t, len(matchLabels), 0)
	val, found := matchLabels["invalid-label"]
	assert.Equal(t, val, "")
	assert.Check(t, !found)
}
