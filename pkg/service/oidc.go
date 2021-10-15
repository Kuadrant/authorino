package service

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
)

var oidcServiceLogger = log.WithName("service").WithName("oidc")

// OidcService implements an HTTP server for OpenID Connect Discovery
type OidcService struct {
	Cache cache.Cache
}

func (o *OidcService) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	urlParts := strings.Split(req.URL.String(), "/")

	realm := strings.Join(urlParts[1:3], "/")
	config := urlParts[3]
	path := strings.Join(urlParts[4:], "/")
	if strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}
	path = "/" + path

	oidcServiceLogger.Info("request received", "realm", realm, "config", config, "path", path)

	var statusCode int
	var responseBody string

	if wristband := o.findWristbandIssuer(realm, config); wristband != nil {
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
		oidcServiceLogger.Error(err, "failed to serve oidc request")
	}
}

func (o *OidcService) findWristbandIssuer(realm string, wristbandConfigName string) common.WristbandIssuer {
	hosts := o.Cache.FindKeys(realm)
	if len(hosts) > 0 {
		for _, config := range o.Cache.Get(hosts[0]).ResponseConfigs {
			respConfigEv, _ := config.(common.ResponseConfigEvaluator)
			if respConfigEv.GetName() == wristbandConfigName {
				return respConfigEv.GetWristbandIssuer()
			}
		}
		return nil
	} else {
		return nil
	}
}
