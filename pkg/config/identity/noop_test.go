package identity

import (
	"encoding/json"
	"testing"

	"gotest.tools/assert"
)

func TestNoopCall(t *testing.T) {
	noop := &Noop{}
	id, err := noop.Call(nil, nil)
	assert.NilError(t, err)
	j, _ := json.Marshal(id)
	assert.Equal(t, string(j), `{"anonymous":true}`)
}
