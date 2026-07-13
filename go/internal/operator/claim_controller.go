package operator

import (
	"context"
	"fmt"
	"time"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	annotationLastActivity = "boilerhouse.dev/last-activity"
	idleCheckInterval      = 30 * time.Second
	releaseFailedRequeue   = 5 * time.Minute
)

// ClaimReconciler reconciles BoilerhouseClaim objects. The implementation is
// split across sibling files to keep each concern focused:
//   - claim_controller.go (this file): phase routing, workload resolution
//   - claim_pods.go:      pod discovery, pool acquisition, cold boot
//   - claim_activate.go:  activation + idle monitoring
//   - claim_release.go:   release / deletion / snapshot extraction
type ClaimReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Snapshots Snapshotter
	Namespace string
	// APIServiceURL is the in-cluster URL injected into tenant Pods as
	// BOILERHOUSE_API_URL. Defaults to http://boilerhouse-api.<Namespace>.svc:3000
	// when empty.
	APIServiceURL string
	// ExtractRetryBackoff controls per-attempt sleep between snapshot extract
	// retries on the release path. Length == attempt count. Defaults to
	// defaultExtractRetryBackoff when nil/empty. Tests pass short delays.
	ExtractRetryBackoff []time.Duration
}

// apiServiceURL returns the configured API URL or a namespace-aware default.
func (r *ClaimReconciler) apiServiceURL() string {
	if r.APIServiceURL != "" {
		return r.APIServiceURL
	}
	ns := r.Namespace
	if ns == "" {
		ns = "boilerhouse"
	}
	return fmt.Sprintf("http://boilerhouse-api.%s.svc:3000", ns)
}

// Reconcile handles a single reconciliation loop for a BoilerhouseClaim.
func (r *ClaimReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	// 1. Get the claim.
	var claim v1alpha1.BoilerhouseClaim
	if err := r.Get(ctx, req.NamespacedName, &claim); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// 2. Handle deletion.
	if !claim.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &claim)
	}

	// 3. Route by phase.
	switch claim.Status.Phase {
	case "Active":
		return r.handleActive(ctx, &claim)
	case "Released":
		// Terminal state — do not reconcile further.
		// The claim persists so the snapshot is discoverable.
		// To revive, delete this claim and create a new one.
		return reconcile.Result{}, nil
	case "ReleaseFailed":
		// Held until manual remediation (force-destroy or retry endpoint).
		// The Pod is deliberately still alive; do not re-enter handleNewClaim.
		return reconcile.Result{}, nil
	default:
		// Empty, Pending, or any other non-active phase: handle as new claim.
		return r.handleNewClaim(ctx, req, &claim)
	}
}

// handleNewClaim processes a claim that is not yet Active (empty or Pending phase).
func (r *ClaimReconciler) handleNewClaim(ctx context.Context, req reconcile.Request, claim *v1alpha1.BoilerhouseClaim) (reconcile.Result, error) {
	// Add finalizer if missing — return early to let next reconcile handle the rest.
	if !controllerutil.ContainsFinalizer(claim, finalizerName) {
		controllerutil.AddFinalizer(claim, finalizerName)
		if err := r.Update(ctx, claim); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	// Set phase to Pending if not already — return early.
	if claim.Status.Phase != "Pending" {
		claim.Status.Phase = "Pending"
		if err := r.Status().Update(ctx, claim); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	// Look up the referenced workload.
	var wl v1alpha1.BoilerhouseWorkload
	wlKey := types.NamespacedName{Name: claim.Spec.WorkloadRef, Namespace: claim.Namespace}
	if err := r.Get(ctx, wlKey, &wl); err != nil {
		if apierrors.IsNotFound(err) {
			return r.setClaimError(ctx, claim, "workload not found")
		}
		return reconcile.Result{}, err
	}
	if wl.Status.Phase != "Ready" {
		return r.setClaimError(ctx, claim, "workload not ready")
	}

	// Ensure the scoped API-token Secret on EVERY reconcile, not only in
	// coldBoot. A resume/re-reconcile can find an existing Pod stuck Pending on a
	// MISSING token Secret (e.g. the Secret was GC'd with a prior claim
	// generation while the Pod lingered), and the "existing Pod" branch below
	// then waits on that Pending Pod forever — never reaching coldBoot, the only
	// other place that provisions the token. Provisioning here (idempotent: it
	// returns the existing Secret or creates it) heals that Pod: the kubelet
	// retries CreateContainerConfigError and starts once the Secret appears.
	// disabled (scopes ["none"]) → no Secret, nothing to heal.
	if _, _, err := r.ensureClaimToken(ctx, claim, &wl); err != nil {
		return reconcile.Result{}, fmt.Errorf("ensuring claim token: %w", err)
	}

	tenantId := claim.Spec.TenantId
	workloadRef := claim.Spec.WorkloadRef
	ns := claim.Namespace

	// Check for existing Pod with tenant label.
	existingPod, err := r.findTenantPod(ctx, ns, tenantId, workloadRef)
	if err != nil {
		return reconcile.Result{}, err
	}
	if existingPod != nil {
		switch existingPod.Status.Phase {
		case corev1.PodRunning:
			return r.activateClaim(ctx, claim, existingPod, "existing")
		case corev1.PodFailed, corev1.PodSucceeded:
			// Pod is terminal — delete it and fall through to cold boot.
			if err := r.Delete(ctx, existingPod); err != nil && !apierrors.IsNotFound(err) {
				return reconcile.Result{}, err
			}
		default:
			// Pod is Pending or Unknown — wait for it rather than creating another.
			return reconcile.Result{RequeueAfter: 2 * time.Second}, nil
		}
	}

	// Check for a pool Pod.
	poolPod, err := r.findPoolPod(ctx, ns, workloadRef)
	if err != nil {
		return reconcile.Result{}, err
	}
	if poolPod != nil {
		return r.claimFromPool(ctx, claim, poolPod, &wl)
	}

	// Cold boot.
	return r.coldBoot(ctx, claim, &wl)
}

// setClaimError sets the claim phase to Error with a detail message.
func (r *ClaimReconciler) setClaimError(ctx context.Context, claim *v1alpha1.BoilerhouseClaim, detail string) (reconcile.Result, error) {
	claim.Status.Phase = "Error"
	claim.Status.Detail = detail
	if err := r.Status().Update(ctx, claim); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

// SetupWithManager registers the ClaimReconciler with the controller manager.
func (r *ClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.BoilerhouseClaim{}).
		Complete(r)
}
