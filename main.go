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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	v1beta1 "github.com/kuadrant/authorino/api/v1beta1"
	v1beta2 "github.com/kuadrant/authorino/api/v1beta2"
	"github.com/kuadrant/authorino/controllers"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/health"
	"github.com/kuadrant/authorino/pkg/index"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/metrics"
	"github.com/kuadrant/authorino/pkg/service"
	"github.com/kuadrant/authorino/pkg/trace"
	"github.com/kuadrant/authorino/pkg/utils"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/go-logr/logr"
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
	"google.golang.org/grpc/reflection"
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
	dirty   string
	gitSHA  string

	scheme = runtime.NewScheme()
	logger logr.Logger
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1beta1.AddToScheme(scheme))
	utilruntime.Must(v1beta2.AddToScheme(scheme))
}

type logOptions struct {
	level string
	mode  string
}

type telemetryOptions struct {
	tracingServiceEndpoint string
	tracingServiceInsecure bool
	tracingServiceTags     []string
}

type commonServerOptions struct {
	log             logOptions
	metricsAddr     string
	healthProbeAddr string
	telemetry       telemetryOptions
}

type authServerOptions struct {
	commonServerOptions
	watchNamespace                 string
	watchedAuthConfigLabelSelector string
	watchedSecretLabelSelector     string
	allowSupersedingHostSubsets    bool
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
	webhookServicePort             int
	enableLeaderElection           bool
	maxHttpRequestBodySize         int64
}

type webhookServerOptions struct {
	commonServerOptions
	port int
}

type keyAuthServerOptions struct{}
type keyWebhookServerOptions struct{}

func main() {
	authServerOpts := &authServerOptions{}
	webhookServerOpts := &webhookServerOptions{}

	cmdRoot := rootCmd()

	cmdRoot.AddCommand(
		authServerCmd(authServerOpts),
		webhookServerCmd(webhookServerOpts),
		versionCmd(),
	)

	ctx := context.WithValue(context.TODO(), keyAuthServerOptions{}, authServerOpts)
	ctx = context.WithValue(ctx, keyWebhookServerOptions{}, webhookServerOpts)

	if err := cmdRoot.ExecuteContext(ctx); err != nil {
		fmt.Println("error: ", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "authorino",
		Short: "Authorino is a Kubernetes-native authorization server.",
	}
}

func authServerCmd(opts *authServerOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Runs the authorization server",
		Run:   runAuthorizationServer,
	}

	cmd.PersistentFlags().StringVar(&opts.watchNamespace, "watch-namespace", utils.EnvVar("WATCH_NAMESPACE", ""), "Kubernetes namespace to watch")
	cmd.PersistentFlags().StringVar(&opts.watchedAuthConfigLabelSelector, "auth-config-label-selector", utils.EnvVar("AUTH_CONFIG_LABEL_SELECTOR", ""), "Kubernetes label selector to filter AuthConfig resources to watch")
	cmd.PersistentFlags().StringVar(&opts.watchedSecretLabelSelector, "secret-label-selector", utils.EnvVar("SECRET_LABEL_SELECTOR", "authorino.kuadrant.io/managed-by=authorino"), "Kubernetes label selector to filter Secret resources to watch")
	cmd.PersistentFlags().BoolVar(&opts.allowSupersedingHostSubsets, "allow-superseding-host-subsets", false, "Enable AuthConfigs to supersede strict host subsets of supersets already taken")
	cmd.PersistentFlags().IntVar(&opts.timeout, "timeout", utils.EnvVar("TIMEOUT", 0), "Server timeout - in milliseconds")
	cmd.PersistentFlags().IntVar(&opts.extAuthGRPCPort, "ext-auth-grpc-port", utils.EnvVar("EXT_AUTH_GRPC_PORT", 50051), "Port number of authorization server - gRPC interface")
	cmd.PersistentFlags().IntVar(&opts.extAuthHTTPPort, "ext-auth-http-port", utils.EnvVar("EXT_AUTH_HTTP_PORT", 5001), "Port number of authorization server - raw HTTP interface")
	cmd.PersistentFlags().StringVar(&opts.tlsCertPath, "tls-cert", utils.EnvVar("TLS_CERT", ""), "Path to the public TLS server certificate file in the file system - authorization server")
	cmd.PersistentFlags().StringVar(&opts.tlsCertKeyPath, "tls-cert-key", utils.EnvVar("TLS_CERT_KEY", ""), "Path to the private TLS server certificate key file in the file system - authorization server")
	cmd.PersistentFlags().IntVar(&opts.oidcHTTPPort, "oidc-http-port", utils.EnvVar("OIDC_HTTP_PORT", 8083), "Port number of OIDC Discovery server for Festival Wristband tokens")
	cmd.PersistentFlags().StringVar(&opts.oidcTLSCertPath, "oidc-tls-cert", utils.EnvVar("OIDC_TLS_CERT", ""), "Path to the public TLS server certificate file in the file system - Festival Wristband OIDC Discovery server")
	cmd.PersistentFlags().StringVar(&opts.oidcTLSCertKeyPath, "oidc-tls-cert-key", utils.EnvVar("OIDC_TLS_CERT_KEY", ""), "Path to the private TLS server certificate key file in the file system - Festival Wristband OIDC Discovery server")
	cmd.PersistentFlags().IntVar(&opts.evaluatorCacheSize, "evaluator-cache-size", utils.EnvVar("EVALUATOR_CACHE_SIZE", 1), "Cache size of each Authorino evaluator if enabled in the AuthConfig - in megabytes")
	cmd.PersistentFlags().BoolVar(&opts.deepMetricsEnabled, "deep-metrics-enabled", utils.EnvVar("DEEP_METRICS_ENABLED", false), "Enable deep metrics at the level of each evaluator when requested in the AuthConfig, exported by the metrics server")
	cmd.PersistentFlags().IntVar(&opts.webhookServicePort, "webhook-service-port", 9443, "Port number of the webhook server")
	cmd.PersistentFlags().BoolVar(&opts.enableLeaderElection, "enable-leader-election", false, "Enable leader election for status updater - ensures only one instance of Authorino tries to update the status of reconciled resources")
	cmd.PersistentFlags().Int64Var(&opts.maxHttpRequestBodySize, "max-http-request-body-size", utils.EnvVar("MAX_HTTP_REQUEST_BODY_SIZE", int64(8192)), "Maximum size of the body of requests accepted in the raw HTTP interface of the authorization server - in bytes")
	registerCommonServerOptions(cmd, &opts.commonServerOptions)

	return cmd
}

func webhookServerCmd(opts *webhookServerOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhooks",
		Short: "Runs the webhook server",
		Run:   runWebhookServer,
	}

	cmd.PersistentFlags().IntVar(&opts.port, "port", 9443, "Port number of the webhook server")
	registerCommonServerOptions(cmd, &opts.commonServerOptions)

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Prints the Authorino version info",
		Run:   printVersion,
	}
}

func registerCommonServerOptions(cmd *cobra.Command, opts *commonServerOptions) {
	cmd.PersistentFlags().StringVar(&opts.log.level, "log-level", utils.EnvVar("LOG_LEVEL", "info"), "Log level")
	cmd.PersistentFlags().StringVar(&opts.log.mode, "log-mode", utils.EnvVar("LOG_MODE", "production"), "Log mode")
	cmd.PersistentFlags().StringVar(&opts.metricsAddr, "metrics-addr", ":8080", "The network address the metrics endpoint binds to")
	cmd.PersistentFlags().StringVar(&opts.healthProbeAddr, "health-probe-addr", ":8081", "The network address the health probe endpoint binds to")
	cmd.PersistentFlags().StringVar(&opts.telemetry.tracingServiceEndpoint, "tracing-service-endpoint", "", "Endpoint URL of the tracing exporter service - use either 'rpc://' or 'http://' scheme")
	cmd.PersistentFlags().BoolVar(&opts.telemetry.tracingServiceInsecure, "tracing-service-insecure", false, "Disable TLS for the tracing service connection")
	cmd.PersistentFlags().StringArrayVar(&opts.telemetry.tracingServiceTags, "tracing-service-tag", []string{}, "Fixed key=value tag to add to emitted traces")
}

func runAuthorizationServer(cmd *cobra.Command, _ []string) {
	opts := cmd.Context().Value(keyAuthServerOptions{}).(*authServerOptions)

	setup(cmd, opts.log, opts.telemetry)

	// global options
	evaluators.EvaluatorCacheSize = opts.evaluatorCacheSize
	metrics.DeepMetricsEnabled = opts.deepMetricsEnabled

	// creates the index of authconfigs
	index := index.NewIndex()

	// starts authorization server
	startExtAuthServerGRPC(index, *opts)
	startExtAuthServerHTTP(index, *opts)

	// starts the oidc discovery server
	startOIDCServer(index, *opts)

	baseManagerOptions := ctrl.Options{
		Scheme:                 scheme,
		WebhookServer:          webhook.NewServer(webhook.Options{Port: opts.webhookServicePort}),
		Metrics:                metricsserver.Options{BindAddress: opts.metricsAddr},
		HealthProbeBindAddress: opts.healthProbeAddr,
		LeaderElection:         false,
	}
	if opts.watchNamespace != "" {
		baseManagerOptions.Cache.DefaultNamespaces = map[string]cache.Config{opts.watchNamespace: {}}
	}

	// sets up the reconciliation manager
	mgr, err := setupManager(baseManagerOptions)
	if err != nil {
		logger.Error(err, "failed to setup reconciliation manager")
		os.Exit(1)
	}

	statusReport := controllers.NewStatusReportMap()
	controllerLogger := log.WithName("controller-runtime").WithName("manager").WithName("controller")

	// sets up the authconfig reconciler
	authConfigReconciler := &controllers.AuthConfigReconciler{
		Client:                      mgr.GetClient(),
		Index:                       index,
		AllowSupersedingHostSubsets: opts.allowSupersedingHostSubsets,
		StatusReport:                statusReport,
		Logger:                      controllerLogger.WithName("authconfig"),
		Scheme:                      mgr.GetScheme(),
		LabelSelector:               controllers.ToLabelSelector(opts.watchedAuthConfigLabelSelector),
		Namespace:                   opts.watchNamespace,
	}
	if err = authConfigReconciler.SetupWithManager(mgr); err != nil {
		logger.Error(err, "failed to setup controller", "controller", "authconfig")
		os.Exit(1)
	}

	// authconfig readiness check
	readinessCheck := health.NewHandler(controllers.AuthConfigsReadyzSubpath, health.Observe(authConfigReconciler))
	if err := mgr.AddReadyzCheck(controllers.AuthConfigsReadyzSubpath, readinessCheck.HandleReadyzCheck); err != nil {
		logger.Error(err, "failed to setup reconciliation readiness check")
		os.Exit(1)
	}

	// sets up the secret reconciler
	if err = (&controllers.SecretReconciler{
		Client:        mgr.GetClient(),
		Logger:        controllerLogger.WithName("secret"),
		Scheme:        mgr.GetScheme(),
		Index:         index,
		LabelSelector: controllers.ToLabelSelector(opts.watchedSecretLabelSelector),
		Namespace:     opts.watchNamespace,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "failed to setup controller", "controller", "secret")
		os.Exit(1)
	}

	// starts the reconciliation manager
	signalHandler := ctrl.SetupSignalHandler()
	logger.Info("starting reconciliation manager")
	go func() {
		if err := mgr.Start(signalHandler); err != nil {
			logger.Error(err, "failed to start reconciliation manager")
			os.Exit(1)
		}
	}()

	// sets up the status update manager
	leaderElectionId := sha256.Sum256([]byte(opts.watchedAuthConfigLabelSelector))
	statusUpdaterOptions := baseManagerOptions
	statusUpdaterOptions.Metrics.BindAddress = "0"    // disabled so it does not clash with the reconciliation manager
	statusUpdaterOptions.HealthProbeBindAddress = "0" // disabled so it does not clash with the reconciliation manager
	statusUpdaterOptions.LeaderElection = opts.enableLeaderElection
	statusUpdaterOptions.LeaderElectionID = fmt.Sprintf("%v.%v", hex.EncodeToString(leaderElectionId[:4]), leaderElectionIDSuffix)
	statusUpdateManager, err := setupManager(statusUpdaterOptions)
	if err != nil {
		logger.Error(err, "failed to setup status update manager")
		os.Exit(1)
	}

	// sets up the authconfig status update controller
	if err = (&controllers.AuthConfigStatusUpdater{
		Client:        statusUpdateManager.GetClient(),
		Logger:        controllerLogger.WithName("authconfig").WithName("statusupdater"),
		StatusReport:  statusReport,
		LabelSelector: controllers.ToLabelSelector(opts.watchedAuthConfigLabelSelector),
	}).SetupWithManager(statusUpdateManager); err != nil {
		logger.Error(err, "failed to create controller", "controller", "authconfigstatusupdate")
	}

	// starts the status update manager
	logger.Info("starting status update manager")
	if err := statusUpdateManager.Start(signalHandler); err != nil {
		logger.Error(err, "failed to start status update manager")
		os.Exit(1)
	}
}

func runWebhookServer(cmd *cobra.Command, _ []string) {
	opts := cmd.Context().Value(keyWebhookServerOptions{}).(*webhookServerOptions)

	setup(cmd, opts.log, opts.telemetry)

	// sets up the webhook manager
	mgr, err := setupManager(ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: opts.metricsAddr},
		HealthProbeBindAddress: opts.healthProbeAddr,
		LeaderElection:         true,
		LeaderElectionID:       fmt.Sprintf("670aa2de.%s", leaderElectionIDSuffix),
		WebhookServer:          webhook.NewServer(webhook.Options{Port: opts.port}),
	})
	if err != nil {
		logger.Error(err, "failed to setup webhook manager")
		os.Exit(1)
	}

	// sets up the authconfig webhook
	if err := (&v1beta2.AuthConfig{}).SetupWebhookWithManager(mgr); err != nil {
		logger.Error(err, "failed to setup authconfig webhook")
		os.Exit(1)
	}

	// starts the webhook manager
	signalHandler := ctrl.SetupSignalHandler()
	logger.Info("starting webhook manager")
	if err := mgr.Start(signalHandler); err != nil {
		logger.Error(err, "failed to start webhook manager")
		os.Exit(1)
	}
}

func setup(cmd *cobra.Command, log logOptions, telemetry telemetryOptions) {
	setupLogger(log)

	logger.Info("", "version", version, "commit", gitSHA, "dirty", dirty)

	// log the command-line args
	if logger.V(1).Enabled() {
		var flags []interface{}
		cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
			flags = append(flags, flag.Name, flag.Value.String())
		})
		logger.V(1).Info("setting up with options", flags...)
	}

	setupTelemetryServices(telemetry)
}

func setupLogger(opts logOptions) {
	logOpts := log.Options{Level: log.ToLogLevel(opts.level), Mode: log.ToLogMode(opts.mode)}
	logger = log.NewLogger(logOpts).WithName("authorino")
	log.SetLogger(logger, logOpts)
}

func setupTelemetryServices(opts telemetryOptions) {
	telemetryLogger := logger.WithName("telemetry")
	otel.SetLogger(telemetryLogger)
	otel.SetErrorHandler(&trace.ErrorHandler{Logger: telemetryLogger})

	if opts.tracingServiceEndpoint != "" {
		tp, err := trace.CreateTraceProvider(trace.Config{
			Endpoint: opts.tracingServiceEndpoint,
			Insecure: opts.tracingServiceInsecure,
			Version:  version,
			Tags:     opts.tracingServiceTags,
		})
		if err != nil {
			telemetryLogger.Error(err, "unable to set trace provider")
		} else {
			otel.SetTracerProvider(tp)
		}
	}

	otel.SetTextMapPropagator(otel_propagation.NewCompositeTextMapPropagator(otel_propagation.TraceContext{}, otel_propagation.Baggage{}))
}

func setupManager(options ctrl.Options) (ctrl.Manager, error) {
	if options.Metrics.BindAddress != "0" {
		options.Metrics.ExtraHandlers = map[string]http.Handler{"/server-metrics": promhttp.Handler()}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		return nil, err
	}

	if options.HealthProbeBindAddress != "0" {
		if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
			return nil, err
		}
	}

	return mgr, nil
}

func startExtAuthServerGRPC(authConfigIndex index.Index, opts authServerOptions) {
	lis, err := listen(opts.extAuthGRPCPort)

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

	tlsEnabled := opts.tlsCertPath != "" && opts.tlsCertKeyPath != ""

	if tlsEnabled {
		if tlsCert, err := tls.LoadX509KeyPair(opts.tlsCertPath, opts.tlsCertKeyPath); err != nil {
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
	reflection.Register(grpcServer)

	envoy_auth.RegisterAuthorizationServer(grpcServer, &service.AuthService{Index: authConfigIndex, Timeout: timeoutMs(opts.timeout)})
	healthpb.RegisterHealthServer(grpcServer, &service.HealthService{})
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	go func() {
		logger.Info("starting grpc auth service", "port", opts.extAuthGRPCPort, "tls", tlsEnabled)

		if err := grpcServer.Serve(lis); err != nil {
			logger.Error(err, "failed to start grpc auth service")
			os.Exit(1)
		}
	}()
}

func startExtAuthServerHTTP(authConfigIndex index.Index, opts authServerOptions) {
	startHTTPService("auth", opts.extAuthHTTPPort, service.HTTPAuthorizationBasePath, opts.tlsCertPath, opts.tlsCertKeyPath, service.NewAuthService(authConfigIndex, timeoutMs(opts.timeout), opts.maxHttpRequestBodySize))
}

func startOIDCServer(authConfigIndex index.Index, opts authServerOptions) {
	startHTTPService("oidc", opts.oidcHTTPPort, service.OIDCBasePath, opts.oidcTLSCertPath, opts.oidcTLSCertKeyPath, &service.OidcService{Index: authConfigIndex})
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

func timeoutMs(timeout int) time.Duration {
	return time.Duration(timeout) * time.Millisecond
}

func printVersion(_ *cobra.Command, _ []string) {
	if dirty == "true" {
		fmt.Printf("%s (%s-dirty)\n", version, gitSHA)
	} else {
		fmt.Printf("%s (%s)\n", version, gitSHA)
	}
}
