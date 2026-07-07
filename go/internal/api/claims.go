package api

import (
	"context"
	"fmt"
	"time"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// acquireOutcome describes what acquireClaim decided to do.
type acquireOutcome int

const (
	// outcomeCreated means a new claim CR was created and must be polled
	// before responding to the caller.
	outcomeCreated acquireOutcome = iota
	// outcomeExistingActive means there was already an Active claim; the
	// caller should return it as-is with 200 OK.
	outcomeExistingActive
)

// acquireClaim orchestrates the claim-instance flow:
//
//  1. If a Released claim exists, clear its finalizer, delete it, and wait
//     briefly for deletion to propagate so the subsequent Create succeeds.
//  2. If an Active claim already exists, return it unchanged (no re-create).
//  3. Otherwise create a fresh BoilerhouseClaim.
//
// It returns the outcome plus the current claim object (which for
// outcomeCreated has only spec/metadata populated — the caller polls status).
func (s *Server) acquireClaim(ctx context.Context, tenantID, wlName string, resume *bool, env map[string]string) (*v1alpha1.BoilerhouseClaim, acquireOutcome, error) {
	claimName := fmt.Sprintf("claim-%s-%s", tenantID, wlName)
	key := types.NamespacedName{Name: claimName, Namespace: s.namespace}

	var existing v1alpha1.BoilerhouseClaim
	if err := s.client.Get(ctx, key, &existing); err == nil {
		switch {
		case !existing.DeletionTimestamp.IsZero():
			// Being torn down — e.g. a release's hibernation snapshot is still
			// running under the finalizer (this can take well over the old 15s
			// bound). Do NOT interrupt it (that would abort the snapshot / risk a
			// phantom box); wait for the operator to finish teardown, then
			// recreate. This is the create side of the cordless reset/resume race.
			s.waitClaimGone(ctx, key)
		case existing.Status.Phase == "Active":
			return &existing, outcomeExistingActive, nil
		default:
			// ANY other existing claim (Released / Error / Pending / empty /
			// unknown) is stale for a fresh claim. Strip its finalizer, delete it,
			// and wait for the operator's cascade before recreating — otherwise the
			// Create below collides with AlreadyExists (the resume-500 bug).
			if len(existing.Finalizers) > 0 {
				existing.Finalizers = nil
				if err := s.client.Update(ctx, &existing); err != nil {
					return nil, outcomeCreated, fmt.Errorf("clear finalizer: %w", err)
				}
			}
			if err := s.client.Delete(ctx, &existing); err != nil && !apierrors.IsNotFound(err) {
				return nil, outcomeCreated, fmt.Errorf("delete old claim: %w", err)
			}
			s.waitClaimGone(ctx, key)
		}
	}

	now := metav1.Now()
	claim := &v1alpha1.BoilerhouseClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      claimName,
			Namespace: s.namespace,
			Labels: map[string]string{
				"boilerhouse.dev/tenant": tenantID,
			},
			Annotations: map[string]string{
				"boilerhouse.dev/last-activity": now.UTC().Format(time.RFC3339),
			},
		},
		Spec: v1alpha1.BoilerhouseClaimSpec{
			TenantId:    tenantID,
			WorkloadRef: wlName,
			Resume:      resume,
			Env:         env,
		},
	}

	if err := s.client.Create(ctx, claim); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// The prior claim's teardown (a release's hibernation snapshot)
			// outlived the wait above and is still terminating. Keep waiting for
			// it to clear, then retry the create once. Bounded by the caller's
			// context (StartBox gives ~90s), so a slow snapshot no longer collides
			// the resume with a hard 500.
			s.waitClaimGone(ctx, key)
			claim.ResourceVersion = ""
			if err := s.client.Create(ctx, claim); err != nil {
				return nil, outcomeCreated, fmt.Errorf("create claim (after teardown wait): %w", err)
			}
			return claim, outcomeCreated, nil
		}
		return nil, outcomeCreated, fmt.Errorf("create claim: %w", err)
	}

	return claim, outcomeCreated, nil
}

// waitClaimGone polls until the claim no longer exists (teardown complete) or a
// short bound elapses. Replaces a fixed sleep so a same-name recreate does not
// race the operator's async finalizer removal. Best-effort — on timeout the
// caller's Create may still conflict, which is no worse than before.
func (s *Server) waitClaimGone(ctx context.Context, key types.NamespacedName) {
	// 60s (ctx-bounded via the select below): a release's hibernation snapshot
	// under the finalizer routinely outlives the old 15s bound, which was the
	// resume "claim already exists" 500. StartBox's ~90s context caps the total.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var c v1alpha1.BoilerhouseClaim
		if err := s.client.Get(ctx, key, &c); apierrors.IsNotFound(err) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// pollClaim waits for the claim to reach Active or Error phase, or for the
// timeout / context to expire. The latest-seen state is returned in all cases.
func (s *Server) pollClaim(ctx context.Context, name string, timeout, interval time.Duration) (*v1alpha1.BoilerhouseClaim, error) {
	deadline := time.Now().Add(timeout)
	key := types.NamespacedName{Name: name, Namespace: s.namespace}

	for time.Now().Before(deadline) {
		var claim v1alpha1.BoilerhouseClaim
		if err := s.client.Get(ctx, key, &claim); err != nil {
			return nil, err
		}

		switch claim.Status.Phase {
		case "Active", "Error":
			return &claim, nil
		}

		select {
		case <-ctx.Done():
			return &claim, ctx.Err()
		case <-time.After(interval):
		}
	}

	// Timeout — return whatever state we can still read.
	var claim v1alpha1.BoilerhouseClaim
	if err := s.client.Get(ctx, key, &claim); err != nil {
		return nil, err
	}
	return &claim, nil
}
