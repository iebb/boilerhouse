package operator

import (
	"context"
	"fmt"
	"time"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// defaultExtractRetryBackoff is the per-attempt sleep schedule used when the
// reconciler's ExtractRetryBackoff is unset. The slice length is the attempt
// count; the last entry is unused (we never sleep after the final attempt).
var defaultExtractRetryBackoff = []time.Duration{1 * time.Second, 4 * time.Second, 16 * time.Second}

// releaseClaim extracts a snapshot (if applicable), deletes the Pod, and sets phase=Released.
// If snapshot extraction fails after all retries, the Pod is preserved and the claim
// transitions to ReleaseFailed so overlay data is not destroyed.
func (r *ClaimReconciler) releaseClaim(ctx context.Context, claim *v1alpha1.BoilerhouseClaim, action string) (reconcile.Result, error) {
	tenantId := claim.Spec.TenantId
	workloadRef := claim.Spec.WorkloadRef
	ns := claim.Namespace

	pod, err := r.findTenantPod(ctx, ns, tenantId, workloadRef)
	if err != nil {
		return reconcile.Result{}, err
	}

	if pod != nil {
		// Extract snapshot before deleting, if action is hibernate and we have overlay dirs.
		if action == "hibernate" && r.Snapshots != nil {
			var wl v1alpha1.BoilerhouseWorkload
			wlKey := types.NamespacedName{Name: workloadRef, Namespace: ns}
			if err := r.Get(ctx, wlKey, &wl); err == nil {
				if wl.Spec.Filesystem != nil && len(wl.Spec.Filesystem.OverlayDirs) > 0 {
					if err := r.extractWithRetry(ctx, pod.Name, tenantId, workloadRef, wl.Spec.Filesystem.OverlayDirs); err != nil {
						ctrl.LoggerFrom(ctx).Error(err, "extracting snapshot on release after retries — keeping pod alive", "tenant", tenantId, "workload", workloadRef)
						return r.markReleaseFailed(ctx, claim, fmt.Sprintf("snapshot extract failed: %v", err))
					}
				}
			}
		}

		// If action=destroy, also delete any stored snapshot.
		if action == "destroy" && r.Snapshots != nil {
			if err := r.Snapshots.DeleteSnapshot(ctx, tenantId, workloadRef); err != nil {
				ctrl.LoggerFrom(ctx).Error(err, "deleting snapshot on destroy", "tenant", tenantId, "workload", workloadRef)
			}
		}

		// Delete the Pod.
		if err := r.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
			return reconcile.Result{}, fmt.Errorf("deleting pod on release: %w", err)
		}
	}

	// Revoke the scoped API token. OwnerReferences would cascade-delete on
	// Claim deletion, but releasing (not deleting) the Claim needs explicit
	// cleanup so a future resume gets a fresh token.
	if err := r.deleteClaimToken(ctx, claim); err != nil {
		return reconcile.Result{}, fmt.Errorf("revoking claim token: %w", err)
	}

	claim.Status.Phase = "Released"
	claim.Status.Detail = fmt.Sprintf("idle timeout (%s)", action)
	if err := r.Status().Update(ctx, claim); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// extractWithRetry calls Snapshots.ExtractAndStore with bounded retries. It
// honours r.ExtractRetryBackoff (per-attempt sleep schedule); when nil/empty
// the production defaults apply. Returns the last error if all attempts fail.
func (r *ClaimReconciler) extractWithRetry(ctx context.Context, podName, tenantId, workloadRef string, overlayDirs []string) error {
	backoff := r.ExtractRetryBackoff
	if len(backoff) == 0 {
		backoff = defaultExtractRetryBackoff
	}

	var lastErr error
	for i, d := range backoff {
		err := r.Snapshots.ExtractAndStore(ctx, podName, tenantId, workloadRef, overlayDirs)
		if err == nil {
			return nil
		}
		lastErr = err

		// Don't sleep after the final attempt.
		if i == len(backoff)-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	return lastErr
}

// markReleaseFailed transitions the claim to ReleaseFailed with the given
// detail. The Pod is intentionally not touched — it stays alive so the
// overlay can still be extracted by a retry or operator intervention.
func (r *ClaimReconciler) markReleaseFailed(ctx context.Context, claim *v1alpha1.BoilerhouseClaim, detail string) (reconcile.Result, error) {
	claim.Status.Phase = "ReleaseFailed"
	claim.Status.Detail = detail
	if err := r.Status().Update(ctx, claim); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: releaseFailedRequeue}, nil
}

// handleDeletion handles the cleanup when a claim is being deleted.
// If the workload has overlay dirs, a snapshot is extracted before the Pod is deleted.
func (r *ClaimReconciler) handleDeletion(ctx context.Context, claim *v1alpha1.BoilerhouseClaim) (reconcile.Result, error) {
	if !controllerutil.ContainsFinalizer(claim, finalizerName) {
		return reconcile.Result{}, nil
	}

	tenantId := claim.Spec.TenantId
	workloadRef := claim.Spec.WorkloadRef
	ns := claim.Namespace

	// Look up the workload to determine idle action and overlay dirs.
	var wl v1alpha1.BoilerhouseWorkload
	wlKey := types.NamespacedName{Name: workloadRef, Namespace: ns}
	idleAction := "hibernate" // default
	if err := r.Get(ctx, wlKey, &wl); err == nil {
		if wl.Spec.Idle != nil && wl.Spec.Idle.Action != "" {
			idleAction = wl.Spec.Idle.Action
		}
	}

	// Find the tenant's Pod.
	pod, err := r.findTenantPod(ctx, ns, tenantId, workloadRef)
	if err != nil {
		return reconcile.Result{}, err
	}

	if pod != nil {
		// Extract snapshot before deletion if action is hibernate.
		// On failure: keep the Pod, hold the finalizer, requeue. The Claim
		// stays in DeletionTimestamp-set / finalizer-held state until a
		// future reconcile succeeds or an operator force-removes the
		// finalizer.
		if idleAction == "hibernate" && r.Snapshots != nil {
			if wl.Spec.Filesystem != nil && len(wl.Spec.Filesystem.OverlayDirs) > 0 {
				if err := r.extractWithRetry(ctx, pod.Name, tenantId, workloadRef, wl.Spec.Filesystem.OverlayDirs); err != nil {
					// If the pod vanished mid-extract a snapshot is impossible, so
					// proceed with deletion rather than holding the finalizer forever:
					// retrying can never succeed and wedges the box (claim stays Active
					// with no pod, which also blocks any same-name recreate — a cordless
					// reset then leaves a phantom box). Only a still-present pod is a
					// transient failure worth requeuing.
					if p, _ := r.findTenantPod(ctx, ns, tenantId, workloadRef); p != nil {
						ctrl.LoggerFrom(ctx).Error(err, "extracting snapshot on deletion after retries — holding finalizer", "tenant", tenantId, "workload", workloadRef)
						return reconcile.Result{RequeueAfter: releaseFailedRequeue}, nil
					}
					ctrl.LoggerFrom(ctx).Info("snapshot skipped on deletion — pod gone; proceeding with cleanup", "tenant", tenantId, "workload", workloadRef)
				}
			}
		}

		// If action=destroy, delete the snapshot too.
		if idleAction == "destroy" && r.Snapshots != nil {
			if err := r.Snapshots.DeleteSnapshot(ctx, tenantId, workloadRef); err != nil {
				ctrl.LoggerFrom(ctx).Error(err, "deleting snapshot on destroy", "tenant", tenantId, "workload", workloadRef)
			}
		}

		// Delete the Pod.
		if err := r.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
			return reconcile.Result{}, fmt.Errorf("deleting pod on claim deletion: %w", err)
		}
	}

	// Revoke the scoped API token. Owner-reference GC would eventually clean
	// this up, but we delete eagerly so the token cannot be used during the
	// window between finalizer-clear and cascade-delete.
	if err := r.deleteClaimToken(ctx, claim); err != nil {
		return reconcile.Result{}, fmt.Errorf("revoking claim token on deletion: %w", err)
	}

	// Remove finalizer.
	controllerutil.RemoveFinalizer(claim, finalizerName)
	if err := r.Update(ctx, claim); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
