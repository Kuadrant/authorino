package service

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
)

// OidcService implements an HTTP server for OpenID Connect Discovery
type OidcService struct {
	Cache cache.Cache
}

func (o *OidcService) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	uri := req.URL.String()

	requestId := md5.Sum([]byte(fmt.Sprint(req)))
	requestLogger := log.WithName("service").WithName("oidc").WithValues("request id", hex.EncodeToString(requestId[:16]), "uri", uri)

	var statusCode int
	var responseBody string

	uriParts := strings.Split(uri, "/")

	if len(uriParts) >= 4 {
		realm := strings.Join(uriParts[1:3], "/")
		config := uriParts[3]
		path := strings.Join(uriParts[4:], "/")
		if strings.HasSuffix(path, "/") {
			path = path[:len(path)-1]
		}
		path = "/" + path

		requestLogger.Info("request received", "realm", realm, "config", config, "path", path)

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
	} else {
		requestLogger.Info("request received")
		statusCode = http.StatusNotFound
		responseBody = "Not found"
	}

	writer.WriteHeader(statusCode)

	if _, err := writer.Write([]byte(responseBody)); err != nil {
		requestLogger.Error(err, "failed to serve oidc request")
	} else {
		requestLogger.Info("response sent", "status", statusCode)
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
