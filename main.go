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
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"os"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	configv1beta1 "github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/controllers"
	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/service"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

const (
	gRPCMaxConcurrentStreams           = 10000
	defaultAuthorinoWatchedSecretLabel = "authorino.3scale.net/managed-by"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	watchNamespace              = common.FetchEnv("WATCH_NAMESPACE", "")
	authorinoWatchedSecretLabel = common.FetchEnv("AUTHORINO_SECRET_LABEL_KEY", defaultAuthorinoWatchedSecretLabel)

	extAuthGRPCPort = common.FetchEnv("EXT_AUTH_GRPC_PORT", "50051")
	tlsCertPath     = common.FetchEnv("TLS_CERT", "")
	tlsCertKeyPath  = common.FetchEnv("TLS_CERT_KEY", "")

	oidcHTTPPort       = common.FetchEnv("OIDC_HTTP_PORT", "8083")
	oidcTLSCertPath    = common.FetchEnv("OIDC_TLS_CERT", "")
	oidcTLSCertKeyPath = common.FetchEnv("OIDC_TLS_CERT_KEY", "")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(configv1beta1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

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
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	cache := cache.NewCache()

	// sets up the auth config reconciler
	authConfigReconciler := &controllers.AuthConfigReconciler{
		Client: mgr.GetClient(),
		Cache:  cache,
		Log:    ctrl.Log.WithName("authorino").WithName("controller").WithName("AuthConfig"),
		Scheme: mgr.GetScheme(),
	}
	if err = authConfigReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AuthConfig")
		os.Exit(1)
	}

	// sets up secret reconciler
	if err = (&controllers.SecretReconciler{
		Client:               mgr.GetClient(),
		Log:                  ctrl.Log.WithName("authorino").WithName("controller").WithName("Secret"),
		Scheme:               mgr.GetScheme(),
		SecretLabel:          authorinoWatchedSecretLabel,
		AuthConfigReconciler: authConfigReconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Secret")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	startExtAuthServer(cache)
	startOIDCServer(cache)

	signalHandler := ctrl.SetupSignalHandler()

	setupLog.Info("Starting manager")

	go func() {
		if err := mgr.Start(signalHandler); err != nil {
			setupLog.Error(err, "problem running manager")
			os.Exit(1)
		}
	}()

	// status update manager
	managerOptions.LeaderElection = enableLeaderElection
	managerOptions.LeaderElectionID = "cb88a58a.authorino.3scale.net"
	managerOptions.MetricsBindAddress = "0"
	statusUpdateManager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions)
	if err != nil {
		setupLog.Error(err, "unable to create status update manager")
		os.Exit(1)
	}

	// sets up auth config status update controller
	if err = (&controllers.AuthConfigStatusUpdater{
		Client: statusUpdateManager.GetClient(),
	}).SetupWithManager(statusUpdateManager); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AuthConfigStatusUpdate")
	}

	setupLog.Info("Starting status update manager")

	if err := statusUpdateManager.Start(signalHandler); err != nil {
		setupLog.Error(err, "problem running status update manager")
		os.Exit(1)
	}
}

func startExtAuthServer(authConfigCache cache.Cache) {
	startExtAuthServerGRPC(authConfigCache)
	startExtAuthServerHTTP(authConfigCache)
}

func startExtAuthServerGRPC(authConfigCache cache.Cache) {
	logger := ctrl.Log.WithName("authorino").WithName("auth")

	if lis, err := net.Listen("tcp", ":"+extAuthGRPCPort); err != nil {
		logger.Error(err, "failed to obtain port for grpc auth service")
		os.Exit(1)
	} else {
		grpcServerOpts := []grpc.ServerOption{grpc.MaxConcurrentStreams(gRPCMaxConcurrentStreams)}

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
	logger := ctrl.Log.WithName("authorino").WithName("oidc")

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
