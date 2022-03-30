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
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	api "github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/controllers"
	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/metrics"
	"github.com/kuadrant/authorino/pkg/service"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	// +kubebuilder:scaffold:imports
)

const (
	envWatchNamespace                 = "WATCH_NAMESPACE"
	envWatchedAuthConfigLabelSelector = "AUTH_CONFIG_LABEL_SELECTOR"
	envWatchedSecretLabelSelector     = "SECRET_LABEL_SELECTOR"
	envLogLevel                       = "LOG_LEVEL"
	envLogMode                        = "LOG_MODE"
	envExtAuthGRPCPort                = "EXT_AUTH_GRPC_PORT"
	envTLSCertPath                    = "TLS_CERT"
	envTLSCertKeyPath                 = "TLS_CERT_KEY"
	envOIDCHTTPPort                   = "OIDC_HTTP_PORT"
	envOIDCTLSCertPath                = "OIDC_TLS_CERT"
	envOIDCTLSCertKeyPath             = "OIDC_TLS_CERT_KEY"
	envDeepMetricsEnabled             = "DEEP_METRICS_ENABLED"
	flagMetricsAddr                   = "metrics-addr"
	flagEnableLeaderElection          = "enable-leader-election"

	defaultWatchNamespace                 = ""
	defaultWatchedAuthConfigLabelSelector = ""
	defaultWatchedSecretLabelSelector     = "authorino.kuadrant.io/managed-by=authorino"
	defaultLogLevel                       = "info"
	defaultLogMode                        = "production"
	defaultExtAuthGRPCPort                = "50051"
	defaultTLSCertPath                    = ""
	defaultTLSCertKeyPath                 = ""
	defaultOIDCHTTPPort                   = "8083"
	defaultOIDCTLSCertPath                = ""
	defaultOIDCTLSCertKeyPath             = ""
	defaultDeepMetricsEnabled             = "false"
	defaultMetricsAddr                    = ":8080"
	defaultEnableLeaderElection           = false

	gRPCMaxConcurrentStreams = 10000
	leaderElectionIDSuffix   = "authorino.kuadrant.io"
)

var (
	watchNamespace                 = fetchEnv(envWatchNamespace, defaultWatchNamespace)
	watchedAuthConfigLabelSelector = fetchEnv(envWatchedAuthConfigLabelSelector, defaultWatchedAuthConfigLabelSelector)
	watchedSecretLabelSelector     = fetchEnv(envWatchedSecretLabelSelector, defaultWatchedSecretLabelSelector)
	logLevel                       = fetchEnv(envLogLevel, defaultLogLevel)
	logMode                        = fetchEnv(envLogMode, defaultLogMode)
	extAuthGRPCPort                = fetchEnv(envExtAuthGRPCPort, defaultExtAuthGRPCPort)
	tlsCertPath                    = fetchEnv(envTLSCertPath, defaultTLSCertPath)
	tlsCertKeyPath                 = fetchEnv(envTLSCertKeyPath, defaultTLSCertKeyPath)
	oidcHTTPPort                   = fetchEnv(envOIDCHTTPPort, defaultOIDCHTTPPort)
	oidcTLSCertPath                = fetchEnv(envOIDCTLSCertPath, defaultOIDCTLSCertPath)
	oidcTLSCertKeyPath             = fetchEnv(envOIDCTLSCertKeyPath, defaultOIDCTLSCertKeyPath)
	deepMetricEnabled              = fetchEnv(envDeepMetricsEnabled, defaultDeepMetricsEnabled)

	scheme  = runtime.NewScheme()
	logOpts = log.Options{Level: log.ToLogLevel(logLevel), Mode: log.ToLogMode(logMode)}
	logger  = log.NewLogger(logOpts).WithName("authorino")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(api.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme

	log.SetLogger(logger, logOpts)

	metrics.DeepMetricsEnabled, _ = strconv.ParseBool(deepMetricEnabled)
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, flagMetricsAddr, defaultMetricsAddr, "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, flagEnableLeaderElection, defaultEnableLeaderElection, "Enable leader election for status updater. Ensures only one instance of Authorino tries to update the status of reconciled resources.")
	flag.Parse()

	logger.V(1).Info("setting up with options",
		envWatchNamespace, watchNamespace,
		envWatchedAuthConfigLabelSelector, watchedAuthConfigLabelSelector,
		envWatchedSecretLabelSelector, watchedSecretLabelSelector,
		envLogLevel, logLevel,
		envLogMode, logMode,
		envExtAuthGRPCPort, extAuthGRPCPort,
		envTLSCertPath, tlsCertPath,
		envTLSCertKeyPath, tlsCertKeyPath,
		envOIDCHTTPPort, oidcHTTPPort,
		envOIDCTLSCertPath, oidcTLSCertPath,
		envOIDCTLSCertKeyPath, oidcTLSCertKeyPath,
		envDeepMetricsEnabled, deepMetricEnabled,
		flagMetricsAddr, metricsAddr,
		flagEnableLeaderElection, enableLeaderElection,
	)

	managerOptions := ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     false,
	}

	if watchNamespace != "" {
		managerOptions.Namespace = watchNamespace
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions)
	if err != nil {
		logger.Error(err, "unable to start manager")
		os.Exit(1)
	}

	cache := cache.NewCache()
	controllerLogger := log.WithName("controller-runtime").WithName("manager").WithName("controller")

	// sets up the auth config reconciler
	authConfigReconciler := &controllers.AuthConfigReconciler{
		Client:        mgr.GetClient(),
		Cache:         cache,
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
		Client:               mgr.GetClient(),
		Logger:               controllerLogger.WithName("secret"),
		Scheme:               mgr.GetScheme(),
		LabelSelector:        controllers.ToLabelSelector(watchedSecretLabelSelector),
		AuthConfigReconciler: authConfigReconciler,
		Namespace:            watchNamespace,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to create controller", "controller", "secret")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	startExtAuthServer(cache)
	startOIDCServer(cache)

	_ = mgr.AddMetricsExtraHandler("/server-metrics", promhttp.Handler())

	signalHandler := ctrl.SetupSignalHandler()

	logger.Info("starting manager")

	go func() {
		if err := mgr.Start(signalHandler); err != nil {
			logger.Error(err, "problem running manager")
			os.Exit(1)
		}
	}()

	// status update manager
	leaderElectionId := md5.Sum([]byte(watchedAuthConfigLabelSelector))
	managerOptions.LeaderElection = enableLeaderElection
	managerOptions.LeaderElectionID = fmt.Sprintf("%v.%v", hex.EncodeToString(leaderElectionId[:4]), leaderElectionIDSuffix)
	managerOptions.MetricsBindAddress = "0"
	statusUpdateManager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions)
	if err != nil {
		logger.Error(err, "unable to start status update manager")
		os.Exit(1)
	}

	// sets up auth config status update controller
	if err = (&controllers.AuthConfigStatusUpdater{
		Client:        statusUpdateManager.GetClient(),
		Logger:        controllerLogger.WithName("authconfig").WithName("statusupdater"),
		Cache:         cache,
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

func startExtAuthServer(authConfigCache cache.Cache) {
	startExtAuthServerGRPC(authConfigCache)
	startExtAuthServerHTTP(authConfigCache)
}

func startExtAuthServerGRPC(authConfigCache cache.Cache) {
	if lis, err := net.Listen("tcp", ":"+extAuthGRPCPort); err != nil {
		logger.Error(err, "failed to obtain port for grpc auth service")
		os.Exit(1)
	} else {
		grpcServerOpts := []grpc.ServerOption{
			grpc.MaxConcurrentStreams(gRPCMaxConcurrentStreams),
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
			grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
		}

		tlsEnabled := tlsCertPath != "" && tlsCertKeyPath != ""
		logger.Info("starting grpc service", "port", extAuthGRPCPort, "tls", tlsEnabled)

		if tlsEnabled {
			if tlsCert, err := tls.LoadX509KeyPair(tlsCertPath, tlsCertKeyPath); err != nil {
				logger.Error(err, "failed to load tls cert")
				os.Exit(1)
			} else {
				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
					ClientAuth:   tls.NoClientCert,
				}
				grpcServerOpts = append(grpcServerOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
			}
		}

		grpcServer := grpc.NewServer(grpcServerOpts...)

		envoy_auth.RegisterAuthorizationServer(grpcServer, &service.AuthService{Cache: authConfigCache})
		healthpb.RegisterHealthServer(grpcServer, &service.HealthService{})
		grpc_prometheus.Register(grpcServer)
		grpc_prometheus.EnableHandlingTimeHistogram()

		go func() {
			if err := grpcServer.Serve(lis); err != nil {
				logger.Error(err, "failed to start grpc service")
				os.Exit(1)
			}
		}()
	}
}

func startExtAuthServerHTTP(authConfigCache cache.Cache) {
	// TODO
}

func startOIDCServer(authConfigCache cache.Cache) {
	if lis, err := net.Listen("tcp", ":"+oidcHTTPPort); err != nil {
		logger.Error(err, "failed to obtain port for http oidc service")
		os.Exit(1)
	} else {
		http.Handle("/", &service.OidcService{
			Cache: authConfigCache,
		})

		tlsEnabled := oidcTLSCertPath != "" && oidcTLSCertKeyPath != ""
		logger.Info("starting oidc service", "port", oidcHTTPPort, "tls", tlsEnabled)

		go func() {
			var err error

			if tlsEnabled {
				err = http.ServeTLS(lis, nil, oidcTLSCertPath, oidcTLSCertKeyPath)
			} else {
				err = http.Serve(lis, nil)
			}

			if err != nil {
				logger.Error(err, "failed to start oidc service")
				os.Exit(1)
			}
		}()
	}
}

func fetchEnv(key string, def string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return def
	} else {
		return val
	}
}
