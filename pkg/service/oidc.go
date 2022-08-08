package service

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/index"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/metrics"
)

const OIDCBasePath = "/"

var (
	oidcServerTotalRequestsMetric  = metrics.NewAuthConfigCounterMetric("oidc_server_requests_total", "Number of get requests received on the OIDC (Festival Wristband) server.", "wristband", "path")
	oidcServerResponseStatusMetric = metrics.NewCounterMetric("oidc_server_response_status", "Status of HTTP response sent by the OIDC (Festival Wristband) server.", "status")
)

func init() {
	metrics.Register(
		oidcServerTotalRequestsMetric,
		oidcServerResponseStatusMetric,
	)
}

// OidcService implements an HTTP server for OpenID Connect Discovery
type OidcService struct {
	Index index.Index
}

func (o *OidcService) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	uri := req.URL
	requestId := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(req))))
	requestLogger := log.WithName("service").WithName("oidc").WithValues("request id", requestId, "uri", uri.String())

	var statusCode int
	var responseBody string

	// Valid paths are in the format: <basePath: OIDCBasePath><authconfigNamespace>/<authconfigName>/<wristbandEvaluatorName>/<pathSuffix>
	path := strings.Split(strings.TrimSuffix(strings.TrimPrefix(uri.Path, OIDCBasePath), "/"), "/")
	var authconfigNamespace, authconfigName, wristbandEvaluatorName string
	unpackPath(path, &authconfigNamespace, &authconfigName, &wristbandEvaluatorName)

	if strings.HasPrefix(uri.Path, OIDCBasePath) && len(path) >= 3 {
		pathSuffix := "/" + strings.Join(path[3:], "/")
		realm := fmt.Sprintf("%s/%s", authconfigNamespace, authconfigName)

		requestLogger.Info("request received", "realm", realm, "config", wristbandEvaluatorName, "path", pathSuffix)

		if wristband := o.findWristbandIssuer(realm, wristbandEvaluatorName); wristband != nil {
			var err error

			switch pathSuffix {
			case "/.well-known/openid-configuration":
				responseBody, err = wristband.OpenIDConfig()
			case "/.well-known/openid-connect/certs":
				responseBody, err = wristband.JWKS()
			default:
				statusCode = http.StatusNotFound
				err = fmt.Errorf("Not found")
			}

			var pathMetric string

			if err == nil {
				statusCode = http.StatusOK
				writer.Header().Add("Content-Type", "application/json")
				pathMetric = pathSuffix
			} else {
				if statusCode == 0 {
					statusCode = http.StatusInternalServerError
				}
				responseBody = err.Error()
			}

			metrics.ReportMetric(oidcServerTotalRequestsMetric, authconfigNamespace, authconfigName, wristbandEvaluatorName, pathMetric)
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

	metrics.ReportMetricWithStatus(oidcServerResponseStatusMetric, strconv.Itoa(statusCode))
}

func (o *OidcService) findWristbandIssuer(realm string, wristbandConfigName string) auth.WristbandIssuer {
	hosts := o.Index.FindKeys(realm)
	if len(hosts) > 0 {
		for _, config := range o.Index.Get(hosts[0]).ResponseConfigs {
			respConfigEv, _ := config.(auth.ResponseConfigEvaluator)
			if respConfigEv.GetName() == wristbandConfigName {
				return respConfigEv.GetWristbandIssuer()
			}
		}
		return nil
	} else {
		return nil
	}
}

func unpackPath(sections []string, vars ...*string) {
	for i, section := range sections {
		if i > len(vars)-1 {
			return
		}
		*vars[i] = section
	}
}
