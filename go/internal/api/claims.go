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
		// A claim already being deleted (DeletionTimestamp set) must NOT be reused
		// as active (its pod is going away → a phantom box) nor collided-with on
		// Create (AlreadyExists). Wait for the operator to finish teardown, then
		// recreate fresh. This is the create side of the cordless reset race.
		if !existing.DeletionTimestamp.IsZero() {
			s.waitClaimGone(ctx, key)
		} else {
			switch existing.Status.Phase {
			case "Released":
				// Revive path: strip finalizer + delete + wait for the operator's
				// cascade to complete before re-creating.
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
			case "Active":
				return &existing, outcomeExistingActive, nil
			}
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
		return nil, outcomeCreated, fmt.Errorf("create claim: %w", err)
	}

	return claim, outcomeCreated, nil
}

// waitClaimGone polls until the claim no longer exists (teardown complete) or a
// short bound elapses. Replaces a fixed sleep so a same-name recreate does not
// race the operator's async finalizer removal. Best-effort — on timeout the
// caller's Create may still conflict, which is no worse than before.
func (s *Server) waitClaimGone(ctx context.Context, key types.NamespacedName) {
	deadline := time.Now().Add(15 * time.Second)
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
