package common

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
)

// CheckContext checks if a go context is still active or done
// When it's done, returns a generic error
//
// func myFunc(ctx context.Context) error {
//   if err := common.CheckContext(ctx); err != nil {
//   	 return err
//   } else {
//     doSomething()
//   }
// }
func CheckContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("Context aborted")
	default:
		return nil
	}
}

// UnmashalJSONResponse unmarshalls a generic HTTP response body into a JSON structure
// Pass optionally a pointer to a byte array to get the raw body of the response object written back
func UnmashalJSONResponse(resp *http.Response, v interface{}, b *[]byte) error {
	// read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if b != nil {
		*b = body
	}

	// check http status ok
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, body)
	}

	// decode as json and return if ok
	err = json.Unmarshal(body, v)
	if err == nil {
		return nil
	}

	// check json response content type
	ct := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}
