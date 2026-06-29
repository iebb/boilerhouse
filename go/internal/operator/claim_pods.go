package operator

import (
	"context"
	"fmt"

	"github.com/zdavison/boilerhouse/go/internal/envoy"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// findTenantPod finds a Pod with the given tenant and workload labels.
func (r *ClaimReconciler) findTenantPod(ctx context.Context, ns, tenantId, workloadRef string) (*corev1.Pod, error) {
	var podList corev1.PodList
	if err := r.List(ctx, &podList,
		client.InNamespace(ns),
		client.MatchingLabels{
			LabelTenant:   tenantId,
			LabelWorkload: workloadRef,
		},
	); err != nil {
		return nil, err
	}
	if len(podList.Items) == 0 {
		return nil, nil
	}
	return &podList.Items[0], nil
}

// findPoolPod finds a ready pool Pod for the given workload.
func (r *ClaimReconciler) findPoolPod(ctx context.Context, ns, workloadRef string) (*corev1.Pod, error) {
	var podList corev1.PodList
	if err := r.List(ctx, &podList,
		client.InNamespace(ns),
		client.MatchingLabels{
			LabelWorkload:   workloadRef,
			LabelPoolStatus: "ready",
		},
	); err != nil {
		return nil, err
	}
	if len(podList.Items) == 0 {
		return nil, nil
	}
	return &podList.Items[0], nil
}

// claimFromPool acquires a pool Pod for a tenant.
// If the tenant has a stored snapshot, the pool Pod is relabeled and the
// snapshot is injected via tar extract; otherwise just relabel.
func (r *ClaimReconciler) claimFromPool(ctx context.Context, claim *v1alpha1.BoilerhouseClaim, poolPod *corev1.Pod, wl *v1alpha1.BoilerhouseWorkload) (reconcile.Result, error) {
	tenantId := claim.Spec.TenantId
	workloadRef := claim.Spec.WorkloadRef

	// Relabel the pool Pod for this tenant.
	poolPod.Labels[LabelTenant] = tenantId
	poolPod.Labels[LabelPoolStatus] = "acquired"
	if err := r.Update(ctx, poolPod); err != nil {
		return reconcile.Result{}, fmt.Errorf("relabeling pool pod: %w", err)
	}

	// Check for a stored snapshot and inject it if present.
	if r.Snapshots != nil {
		hasSnap, err := r.Snapshots.HasSnapshot(ctx, tenantId, workloadRef)
		if err != nil {
			// Log but don't fail the claim — the Pod is still usable.
			ctrl.LoggerFrom(ctx).Error(err, "checking for snapshot", "tenant", tenantId, "workload", workloadRef)
		} else if hasSnap {
			if err := r.Snapshots.InjectSnapshot(ctx, poolPod.Name, tenantId, workloadRef); err != nil {
				ctrl.LoggerFrom(ctx).Error(err, "injecting snapshot", "tenant", tenantId, "workload", workloadRef)
			} else {
				return r.activateClaim(ctx, claim, poolPod, "pool+data")
			}
		}
	}

	return r.activateClaim(ctx, claim, poolPod, "pool")
}

// coldBoot creates a new Pod from scratch for a tenant.
// If a snapshot exists, it will be injected once the Pod is running.
// Note: snapshot injection requires the Pod to be running, so for cold boots
// the injection happens on a subsequent reconcile when the Pod is ready.
func (r *ClaimReconciler) coldBoot(ctx context.Context, claim *v1alpha1.BoilerhouseClaim, wl *v1alpha1.BoilerhouseWorkload) (reconcile.Result, error) {
	// Provision the scoped API token *before* Pod creation so the Pod can
	// reference the Secret via secretKeyRef. If APIAccess.Scopes is ["none"]
	// this returns disabled=true and no Secret is created.
	tokenSecret, disabled, err := r.ensureClaimToken(ctx, claim, wl)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("ensuring claim token: %w", err)
	}
	if disabled {
		tokenSecret = ""
	}

	pod, err := r.createTenantPod(ctx, claim, wl, tokenSecret)
	if err != nil {
		return reconcile.Result{}, err
	}

	return r.activateClaim(ctx, claim, pod, "cold")
}

// createTenantPod translates a workload spec and creates the Pod.
// If the workload has network credentials, it resolves them, generates Envoy
// config and TLS certs, creates a ConfigMap, and injects the sidecar.
// When tokenSecret is non-empty, the Pod receives BOILERHOUSE_API_KEY +
// BOILERHOUSE_API_URL env vars sourced from that Secret.
func (r *ClaimReconciler) createTenantPod(ctx context.Context, claim *v1alpha1.BoilerhouseClaim, wl *v1alpha1.BoilerhouseWorkload, tokenSecret string) (*corev1.Pod, error) {
	suffix := randomSuffix()
	instanceId := fmt.Sprintf("%s-%s-%s", claim.Spec.WorkloadRef, claim.Spec.TenantId, suffix)

	opts := TranslateOpts{
		InstanceId:       instanceId,
		WorkloadName:     claim.Spec.WorkloadRef,
		TenantId:         claim.Spec.TenantId,
		Namespace:        claim.Namespace,
		ImageRef:         ResolvedImageRef(wl),
		ClaimTokenSecret: tokenSecret,
		APIServiceURL:    r.apiServiceURL(),
		ClaimEnv:         claim.Spec.Env,
	}

	// Build the egress proxy when the workload injects credentials OR restricts
	// egress (restricted access / a non-empty allowlist). Previously this only
	// fired for credentials, so an allowlist-only "restricted" workload got no
	// sidecar and therefore NO egress enforcement at all. The proxy sidecar +
	// iptables redirect then deny everything except the allowlist (SNI
	// passthrough) and the credential domains (MITM).
	if wl.Spec.Network != nil && (len(wl.Spec.Network.Credentials) > 0 ||
		wl.Spec.Network.Access == "restricted" ||
		len(wl.Spec.Network.Allowlist) > 0) {
		proxyConfig, err := BuildProxyConfig(ctx, r.Client, r.Namespace, wl)
		if err != nil {
			return nil, fmt.Errorf("building proxy config: %w", err)
		}
		opts.ProxyConfig = proxyConfig
	}

	result, err := Translate(wl.Spec, opts)
	if err != nil {
		return nil, fmt.Errorf("translating workload: %w", err)
	}

	// Create ConfigMap before Pod if sidecar is injected.
	if result.ConfigMap != nil {
		if err := r.Create(ctx, result.ConfigMap); err != nil {
			return nil, fmt.Errorf("creating proxy configmap: %w", err)
		}
	}

	if err := r.Create(ctx, result.Pod); err != nil {
		return nil, fmt.Errorf("creating tenant pod: %w", err)
	}

	return result.Pod, nil
}

// BuildProxyConfig resolves a workload's credentials, generates TLS material
// and Envoy YAML. All credentials are resolved from global Secrets in the
// operator's namespace, so the resulting ProxyConfig is tenant-agnostic —
// the same config is valid for pool pods and tenant-specific pods alike.
func BuildProxyConfig(ctx context.Context, c client.Client, namespace string, wl *v1alpha1.BoilerhouseWorkload) (*ProxyConfig, error) {
	resolved, err := ResolveCredentials(ctx, c, namespace, wl.Spec.Network.Credentials)
	if err != nil {
		return nil, fmt.Errorf("resolving credentials: %w", err)
	}

	// Collect domains for TLS.
	var domains []string
	for _, rc := range resolved {
		domains = append(domains, rc.Domain)
	}

	// Generate TLS material.
	tlsMaterial, err := envoy.GenerateTLS(domains)
	if err != nil {
		return nil, fmt.Errorf("generating TLS material: %w", err)
	}

	// Generate Envoy config YAML.
	envoyCfg := envoy.EnvoyConfig{
		Credentials: resolved,
		TLS:         tlsMaterial,
	}
	if wl.Spec.Network.Allowlist != nil {
		envoyCfg.Allowlist = wl.Spec.Network.Allowlist
	}

	envoyYAML, err := envoy.GenerateEnvoyYAML(envoyCfg)
	if err != nil {
		return nil, fmt.Errorf("generating envoy config: %w", err)
	}

	return &ProxyConfig{
		EnvoyYAML: envoyYAML,
		CACert:    tlsMaterial.CACert,
		TLS:       tlsMaterial,
	}, nil
}
