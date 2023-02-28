/*
Copyright 2020 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	api "github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/controllers"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/health"
	"github.com/kuadrant/authorino/pkg/index"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/metrics"
	"github.com/kuadrant/authorino/pkg/service"
	"github.com/kuadrant/authorino/pkg/trace"
	"github.com/kuadrant/authorino/pkg/utils"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	otel_grpc "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	otel_http "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	otel_propagation "go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	// +kubebuilder:scaffold:imports
)

const (
	gRPCMaxConcurrentStreams = 10000
	leaderElectionIDSuffix   = "authorino.kuadrant.io"
)

var (
	// ldflags
	version string

	// option flags
	watchNamespace                 string
	watchedAuthConfigLabelSelector string
	watchedSecretLabelSelector     string
	logLevel                       string
	logMode                        string
	timeout                        int
	extAuthGRPCPort                int
	extAuthHTTPPort                int
	tlsCertPath                    string
	tlsCertKeyPath                 string
	oidcHTTPPort                   int
	oidcTLSCertPath                string
	oidcTLSCertKeyPath             string
	evaluatorCacheSize             int
	deepMetricsEnabled             bool
	metricsAddr                    string
	healthProbeAddr                string
	enableLeaderElection           bool
	maxHttpRequestBodySize         int64
	observabilityServiceEndpoint   string
	observabilityServiceSeed       string

	scheme = runtime.NewScheme()

	logger logr.Logger
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(api.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	cmdRoot := &cobra.Command{
		Use:   "authorino",
		Short: "Authorino is a Kubernetes-native authorization server.",
	}

	cmdServer := &cobra.Command{
		Use:   "server",
		Short: "Runs the authorization server",
		Run:   run,
	}

	cmdServer.PersistentFlags().StringVar(&watchNamespace, "watch-namespace", utils.EnvVar("WATCH_NAMESPACE", ""), "Kubernetes namespace to watch")
	cmdServer.PersistentFlags().StringVar(&watchedAuthConfigLabelSelector, "auth-config-label-selector", utils.EnvVar("AUTH_CONFIG_LABEL_SELECTOR", ""), "Kubernetes label selector to filter AuthConfig resources to watch")
	cmdServer.PersistentFlags().StringVar(&watchedSecretLabelSelector, "secret-label-selector", utils.EnvVar("SECRET_LABEL_SELECTOR", "authorino.kuadrant.io/managed-by=authorino"), "Kubernetes label selector to filter Secret resources to watch")
	cmdServer.PersistentFlags().StringVar(&logLevel, "log-level", utils.EnvVar("LOG_LEVEL", "info"), "Log level")
	cmdServer.PersistentFlags().StringVar(&logMode, "log-mode", utils.EnvVar("LOG_MODE", "production"), "Log mode")
	cmdServer.PersistentFlags().IntVar(&timeout, "timeout", utils.EnvVar("TIMEOUT", 0), "Server timeout - in milliseconds")
	cmdServer.PersistentFlags().IntVar(&extAuthGRPCPort, "ext-auth-grpc-port", utils.EnvVar("EXT_AUTH_GRPC_PORT", 50051), "Port number of authorization server - gRPC interface")
	cmdServer.PersistentFlags().IntVar(&extAuthHTTPPort, "ext-auth-http-port", utils.EnvVar("EXT_AUTH_HTTP_PORT", 5001), "Port number of authorization server - raw HTTP interface")
	cmdServer.PersistentFlags().StringVar(&tlsCertPath, "tls-cert", utils.EnvVar("TLS_CERT", ""), "Path to the public TLS server certificate file in the file system - authorization server")
	cmdServer.PersistentFlags().StringVar(&tlsCertKeyPath, "tls-cert-key", utils.EnvVar("TLS_CERT_KEY", ""), "Path to the private TLS server certificate key file in the file system - authorization server")
	cmdServer.PersistentFlags().IntVar(&oidcHTTPPort, "oidc-http-port", utils.EnvVar("OIDC_HTTP_PORT", 8083), "Port number of OIDC Discovery server for Festival Wristband tokens")
	cmdServer.PersistentFlags().StringVar(&oidcTLSCertPath, "oidc-tls-cert", utils.EnvVar("OIDC_TLS_CERT", ""), "Path to the public TLS server certificate file in the file system - Festival Wristband OIDC Discovery server")
	cmdServer.PersistentFlags().StringVar(&oidcTLSCertKeyPath, "oidc-tls-cert-key", utils.EnvVar("OIDC_TLS_CERT_KEY", ""), "Path to the private TLS server certificate key file in the file system - Festival Wristband OIDC Discovery server")
	cmdServer.PersistentFlags().IntVar(&evaluatorCacheSize, "evaluator-cache-size", utils.EnvVar("EVALUATOR_CACHE_SIZE", 1), "Cache size of each Authorino evaluator if enabled in the AuthConfig - in megabytes")
	cmdServer.PersistentFlags().BoolVar(&deepMetricsEnabled, "deep-metrics-enabled", utils.EnvVar("DEEP_METRICS_ENABLED", false), "Enable deep metrics at the level of each evaluator when requested in the AuthConfig, exported by the metrics server")
	cmdServer.PersistentFlags().StringVar(&metricsAddr, "metrics-addr", ":8080", "The network address the metrics endpoint binds to")
	cmdServer.PersistentFlags().StringVar(&healthProbeAddr, "health-probe-addr", ":8081", "The network address the health probe endpoint binds to")
	cmdServer.PersistentFlags().BoolVar(&enableLeaderElection, "enable-leader-election", false, "Enable leader election for status updater - ensures only one instance of Authorino tries to update the status of reconciled resources")
	cmdServer.PersistentFlags().Int64Var(&maxHttpRequestBodySize, "max-http-request-body-size", utils.EnvVar("MAX_HTTP_REQUEST_BODY_SIZE", int64(8192)), "Maximum size of the body of requests accepted in the raw HTTP interface of the authorization server - in bytes")
	cmdServer.PersistentFlags().StringVar(&observabilityServiceSeed, "observability-service-seed", "", "Seed attribute of the OpenTelemetry resource")

	cmdVersion := &cobra.Command{
		Use:   "version",
		Short: "Prints the Authorino version info",
		Run:   printVersion,
	}

	cmdRoot.AddCommand(cmdServer, cmdVersion)

	if err := cmdRoot.Execute(); err != nil {
		fmt.Println("error: ", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, _ []string) {
	logOpts := log.Options{Level: log.ToLogLevel(logLevel), Mode: log.ToLogMode(logMode)}
	logger = log.NewLogger(logOpts).WithName("authorino")
	log.SetLogger(logger, logOpts)

	logger.Info("booting up authorino", "version", version)

	var flags []interface{}
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		flags = append(flags, flag.Name, flag.Value.String())
	})

	logger.V(1).Info("setting up with options", flags...)

	evaluators.EvaluatorCacheSize = evaluatorCacheSize
	metrics.DeepMetricsEnabled = deepMetricsEnabled

	managerOptions := ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		HealthProbeBindAddress: healthProbeAddr,
		Port:                   9443,
		LeaderElection:         false,
	}

	if watchNamespace != "" {
		managerOptions.Namespace = watchNamespace
	}

	if observabilityServiceEndpoint != "" {
		otel.SetLogger(logger)
		tp, err := trace.CreateTraceProvider(observabilityServiceEndpoint, version, observabilityServiceSeed)
		if err != nil {
			logger.Error(err, "unable to create traceprovider")
			os.Exit(1)
		}
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(otel_propagation.NewCompositeTextMapPropagator(otel_propagation.TraceContext{}, otel_propagation.Baggage{}))
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions)
	if err != nil {
		logger.Error(err, "unable to start manager")
		os.Exit(1)
	}

	index := index.NewIndex()
	statusReport := controllers.NewStatusReportMap()
	controllerLogger := log.WithName("controller-runtime").WithName("manager").WithName("controller")

	// sets up the auth config reconciler
	authConfigReconciler := &controllers.AuthConfigReconciler{
		Client:        mgr.GetClient(),
		Index:         index,
		StatusReport:  statusReport,
		Logger:        controllerLogger.WithName("authconfig"),
		Scheme:        mgr.GetScheme(),
		LabelSelector: controllers.ToLabelSelector(watchedAuthConfigLabelSelector),
		Namespace:     watchNamespace,
	}
	if err = authConfigReconciler.SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to create controller", "controller", "authconfig")
		os.Exit(1)
	}

	// sets up secret reconciler
	if err = (&controllers.SecretReconciler{
		Client:        mgr.GetClient(),
		Logger:        controllerLogger.WithName("secret"),
		Scheme:        mgr.GetScheme(),
		Index:         index,
		LabelSelector: controllers.ToLabelSelector(watchedSecretLabelSelector),
		Namespace:     watchNamespace,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to create controller", "controller", "secret")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	startExtAuthServerGRPC(index)
	startExtAuthServerHTTP(index)
	startOIDCServer(index)

	if err := mgr.AddMetricsExtraHandler("/server-metrics", promhttp.Handler()); err != nil {
		logger.Error(err, "unable to set up controller metrics server")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up controller health check")
		os.Exit(1)
	}

	readinessCheck := health.NewHandler(controllers.AuthConfigsReadyzSubpath, health.Observe(authConfigReconciler))
	if err := mgr.AddReadyzCheck(controllers.AuthConfigsReadyzSubpath, readinessCheck.HandleReadyzCheck); err != nil {
		logger.Error(err, "unable to set up controller readiness check")
		os.Exit(1)
	}

	signalHandler := ctrl.SetupSignalHandler()

	logger.Info("starting manager")

	go func() {
		if err := mgr.Start(signalHandler); err != nil {
			logger.Error(err, "problem running manager")
			os.Exit(1)
		}
	}()

	// status update manager
	leaderElectionId := sha256.Sum256([]byte(watchedAuthConfigLabelSelector))
	managerOptions.LeaderElection = enableLeaderElection
	managerOptions.LeaderElectionID = fmt.Sprintf("%v.%v", hex.EncodeToString(leaderElectionId[:4]), leaderElectionIDSuffix)
	managerOptions.MetricsBindAddress = "0"
	managerOptions.HealthProbeBindAddress = "0"
	statusUpdateManager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions)
	if err != nil {
		logger.Error(err, "unable to start status update manager")
		os.Exit(1)
	}

	// sets up auth config status update controller
	if err = (&controllers.AuthConfigStatusUpdater{
		Client:        statusUpdateManager.GetClient(),
		Logger:        controllerLogger.WithName("authconfig").WithName("statusupdater"),
		StatusReport:  statusReport,
		LabelSelector: controllers.ToLabelSelector(watchedAuthConfigLabelSelector),
	}).SetupWithManager(statusUpdateManager); err != nil {
		logger.Error(err, "unable to create controller", "controller", "authconfigstatusupdate")
	}

	logger.Info("starting status update manager")

	if err := statusUpdateManager.Start(signalHandler); err != nil {
		logger.Error(err, "problem running status update manager")
		os.Exit(1)
	}
}

func startExtAuthServerGRPC(authConfigIndex index.Index) {
	lis, err := listen(extAuthGRPCPort)

	if err != nil {
		logger.Error(err, "failed to obtain port for the grpc auth service")
		os.Exit(1)
	}

	if lis == nil {
		logger.Info("disabling grpc auth service")
		return
	}

	grpcServerOpts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(gRPCMaxConcurrentStreams),
		grpc.ChainStreamInterceptor(grpc_prometheus.StreamServerInterceptor, otel_grpc.StreamServerInterceptor()),
		grpc.ChainUnaryInterceptor(grpc_prometheus.UnaryServerInterceptor, otel_grpc.UnaryServerInterceptor()),
	}

	tlsEnabled := tlsCertPath != "" && tlsCertKeyPath != ""

	if tlsEnabled {
		if tlsCert, err := tls.LoadX509KeyPair(tlsCertPath, tlsCertKeyPath); err != nil {
			logger.Error(err, "failed to load tls cert for the grpc auth service")
			os.Exit(1)
		} else {
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				ClientAuth:   tls.NoClientCert,
				MinVersion:   tls.VersionTLS12,
			}
			grpcServerOpts = append(grpcServerOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}
	}

	grpcServer := grpc.NewServer(grpcServerOpts...)

	envoy_auth.RegisterAuthorizationServer(grpcServer, &service.AuthService{Index: authConfigIndex, Timeout: timeoutMs()})
	healthpb.RegisterHealthServer(grpcServer, &service.HealthService{})
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	go func() {
		logger.Info("starting grpc auth service", "port", extAuthGRPCPort, "tls", tlsEnabled)

		if err := grpcServer.Serve(lis); err != nil {
			logger.Error(err, "failed to start grpc auth service")
			os.Exit(1)
		}
	}()
}

func startExtAuthServerHTTP(authConfigIndex index.Index) {
	startHTTPService("auth", extAuthHTTPPort, service.HTTPAuthorizationBasePath, tlsCertPath, tlsCertKeyPath, service.NewAuthService(authConfigIndex, timeoutMs(), maxHttpRequestBodySize))
}

func startOIDCServer(authConfigIndex index.Index) {
	startHTTPService("oidc", oidcHTTPPort, service.OIDCBasePath, oidcTLSCertPath, oidcTLSCertKeyPath, &service.OidcService{Index: authConfigIndex})
}

func startHTTPService(name string, port int, basePath, tlsCertPath, tlsCertKeyPath string, handler http.Handler) {
	lis, err := listen(port)

	if err != nil {
		logger.Error(err, fmt.Sprintf("failed to obtain port for the http %s service", name))
		os.Exit(1)
	}

	if lis == nil {
		logger.Info(fmt.Sprintf("disabling http %s service", name))
		return
	}

	http.Handle(basePath, otel_http.NewHandler(handler, name))

	tlsEnabled := tlsCertPath != "" && tlsCertKeyPath != ""

	go func() {
		var err error

		logger.Info(fmt.Sprintf("starting http %s service", name), "port", port, "tls", tlsEnabled)

		if tlsEnabled {
			server := &http.Server{
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					ClientAuth: tls.RequestClientCert,
				},
			}
			err = server.ServeTLS(lis, tlsCertPath, tlsCertKeyPath)
		} else {
			err = http.Serve(lis, nil)
		}

		if err != nil {
			logger.Error(err, fmt.Sprintf("failed to start http %s service", name))
			os.Exit(1)
		}
	}()
}

func listen(port int) (net.Listener, error) {
	if port == 0 {
		return nil, nil
	}

	if lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port)); err != nil {
		return nil, err
	} else {
		return lis, nil
	}
}

func fetchEnv(key string, def interface{}) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fmt.Sprint(def)
	} else {
		return val
	}
}

func timeoutMs() time.Duration {
	return time.Duration(timeout) * time.Millisecond
}

func printVersion(_ *cobra.Command, _ []string) {
	fmt.Println("Authorino", version)
}
