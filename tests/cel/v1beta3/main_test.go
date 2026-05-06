/*
Copyright 2026 Red Hat, Inc.

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

package v1beta3_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuadrant/authorino/api/v1beta3"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var k8sClient client.Client

func TestMain(m *testing.M) {
	scheme := runtime.NewScheme()

	utilruntime.Must(v1beta3.AddToScheme(scheme))

	// Add core APIs in case we refer secrets, services and configmaps
	utilruntime.Must(corev1.AddToScheme(scheme))

	// The version used here MUST reflect the available versions at
	// controller-runtime repo: https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/HEAD/envtest-releases.yaml
	// K8S_VERSION environment variable can be used by setup-envtest (in the Makefile)
	// to download a specific Kubernetes version. If not set, the latest GA will be used.
	testEnv := &envtest.Environment{
		Scheme:                scheme,
		UseExistingCluster:    new(bool), // false - always use envtest
		ErrorIfCRDPathMissing: true,
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{
				filepath.Join("..", "..", "..", "install", "crd"),
			},
			CleanUpAfterUse: true,
		},
	}

	restConfig, err := testEnv.Start()
	if err != nil {
		panic(fmt.Sprintf("Error initializing test environment: %v", err))
	}

	k8sClient, err = client.New(restConfig, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		panic(fmt.Sprintf("Error initializing Kubernetes client: %v", err))
	}

	rc := m.Run()

	if err := testEnv.Stop(); err != nil {
		panic(fmt.Sprintf("error stopping test environment: %v", err))
	}

	os.Exit(rc)
}

func celErrorStringMatches(got, want string) bool {
	// Starting in k8s v1.32, some CEL error messages changed to use "more" instead of "longer"
	alternativeWant := strings.ReplaceAll(want, "more", "longer")

	return strings.Contains(got, want) || strings.Contains(got, alternativeWant)
}
