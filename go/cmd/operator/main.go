package main

import (
	"os"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	"github.com/zdavison/boilerhouse/go/internal/operator"
)

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	log := ctrl.Log.WithName("operator")

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)

	namespace := os.Getenv("K8S_NAMESPACE")
	if namespace == "" {
		namespace = "boilerhouse"
	}

	metricsAddr := os.Getenv("METRICS_PORT")
	if metricsAddr == "" {
		metricsAddr = ":9464"
	} else {
		metricsAddr = ":" + metricsAddr
	}

	leaderElect := os.Getenv("LEADER_ELECT") != "false"

	healthAddr := os.Getenv("HEALTH_PORT")
	if healthAddr == "" {
		healthAddr = ":8081"
	} else {
		healthAddr = ":" + healthAddr
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		LeaderElection:          leaderElect,
		LeaderElectionID:        "boilerhouse-operator",
		LeaderElectionNamespace: namespace,
		HealthProbeBindAddress:  healthAddr,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
	})
	if err != nil {
		log.Error(err, "unable to create manager")
		os.Exit(1)
	}

	// Register all controllers.
	workloadsDir := os.Getenv("WORKLOADS_DIR")

	if err := (&operator.WorkloadReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		WorkloadsDir: workloadsDir,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create controller", "controller", "WorkloadReconciler")
		os.Exit(1)
	}

	if err := (&operator.PoolReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create controller", "controller", "PoolReconciler")
		os.Exit(1)
	}

	snapshots := operator.NewSnapshotManager(namespace, mgr.GetClient(), mgr.GetConfig())

	if err := (&operator.ClaimReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Snapshots: snapshots,
		Namespace: namespace,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create controller", "controller", "ClaimReconciler")
		os.Exit(1)
	}

	if err := (&operator.TriggerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create controller", "controller", "TriggerReconciler")
		os.Exit(1)
	}

	// Add health and readiness checks.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	log.Info("starting operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "operator exited with error")
		os.Exit(1)
	}
}
