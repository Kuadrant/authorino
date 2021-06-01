package service

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/common"

	ctrl "sigs.k8s.io/controller-runtime"
)

var oidcServiceLog = ctrl.Log.WithName("authorino").WithName("OidcService")

// OidcService implements an HTTP server for OpenID Connect Discovery
type OidcService struct {
	Cache cache.Cache
}

func (o *OidcService) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	urlParts := strings.Split(req.URL.String(), "/")

	realm := strings.Join(urlParts[1:3], "/")
	path := strings.Join(urlParts[3:], "/")
	if strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}
	path = "/" + path

	oidcServiceLog.Info("request received", "realm", realm, "path", path)

	var statusCode int
	var responseBody string

	if wristband := o.findWristbandIssuer(realm); wristband != nil {
		var err error

		switch path {
		case "/.well-known/openid-configuration":
			responseBody, err = wristband.OpenIDConfig()
		case "/.well-known/openid-connect/certs":
			responseBody, err = wristband.JWKS()
		default:
			statusCode = http.StatusNotFound
			err = fmt.Errorf("Not found")
		}

		if err == nil {
			statusCode = http.StatusOK
			writer.Header().Add("Content-Type", "application/json")
		} else {
			if statusCode == 0 {
				statusCode = http.StatusInternalServerError
			}
			responseBody = err.Error()
		}
	} else {
		statusCode = http.StatusNotFound
		responseBody = "Not found"
	}

	writer.WriteHeader(statusCode)

	if _, err := writer.Write([]byte(responseBody)); err != nil {
		oidcServiceLog.Error(err, "failed to serve oidc request")
	}
}

func (o *OidcService) findWristbandIssuer(realm string) common.WristbandIssuer {
	hosts := o.Cache.FindKeys(realm)
	if len(hosts) > 0 {
		return o.Cache.Get(hosts[0]).Wristband
	} else {
		return nil
	}
}
