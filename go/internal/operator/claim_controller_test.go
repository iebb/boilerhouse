package operator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestClaimController_ColdBootNewTenant(t *testing.T) {
	ctx, k8sClient, cleanup := setupEnvtest(t)
	defer cleanup()

	// Create and reconcile a Ready workload.
	wlReconciler := &WorkloadReconciler{
		Client: k8sClient,
		Scheme: k8sClient.Scheme(),
	}

	wl := &v1alpha1.BoilerhouseWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cold-wl",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseWorkloadSpec{
			Version: "1.0.0",
			Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
			Resources: v1alpha1.WorkloadResources{
				VCPUs:    1,
				MemoryMb: 256,
				DiskGb:   5,
			},
			Network: &v1alpha1.WorkloadNetwork{
				Expose: []v1alpha1.NetworkExposePort{{Guest: 8080}},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, wl))
	wlKey := types.NamespacedName{Name: "cold-wl", Namespace: "default"}
	for i := 0; i < 3; i++ {
		_, err := wlReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: wlKey})
		require.NoError(t, err)
	}

	// Verify workload is Ready.
	var readyWl v1alpha1.BoilerhouseWorkload
	require.NoError(t, k8sClient.Get(ctx, wlKey, &readyWl))
	require.Equal(t, "Ready", readyWl.Status.Phase)

	// Create a claim.
	claim := &v1alpha1.BoilerhouseClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cold-claim",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseClaimSpec{
			TenantId:    "alice",
			WorkloadRef: "cold-wl",
		},
	}
	require.NoError(t, k8sClient.Create(ctx, claim))

	// Reconcile the claim.
	claimReconciler := &ClaimReconciler{
		Client:    k8sClient,
		Scheme:    k8sClient.Scheme(),
		Namespace: "default",
	}

	// Multiple reconciles: finalizer add, Pending, then cold boot to Active.
	claimKey := types.NamespacedName{Name: "cold-claim", Namespace: "default"}
	for i := 0; i < 5; i++ {
		_, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: claimKey})
		require.NoError(t, err)
		populateEmptyPodIPs(t, ctx, k8sClient, "default")
	}

	// Verify claim status.
	var updatedClaim v1alpha1.BoilerhouseClaim
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "cold-claim", Namespace: "default"}, &updatedClaim))
	assert.Equal(t, "Active", updatedClaim.Status.Phase)
	assert.Equal(t, "cold", updatedClaim.Status.Source)
	assert.NotEmpty(t, updatedClaim.Status.InstanceId)
	assert.NotNil(t, updatedClaim.Status.ClaimedAt)
	assert.Contains(t, updatedClaim.Finalizers, finalizerName)

	// Verify Pod was created with correct labels.
	var podList corev1.PodList
	require.NoError(t, k8sClient.List(ctx, &podList,
		client.InNamespace("default"),
		client.MatchingLabels{
			LabelTenant:   "alice",
			LabelWorkload: "cold-wl",
		},
	))
	require.Len(t, podList.Items, 1)
	pod := podList.Items[0]
	assert.Equal(t, "alice", pod.Labels[LabelTenant])
	assert.Equal(t, "cold-wl", pod.Labels[LabelWorkload])
	assert.Equal(t, "true", pod.Labels[LabelManaged])
}

func TestClaimController_ColdBootWithOverlayDirs(t *testing.T) {
	ctx, k8sClient, cleanup := setupEnvtest(t)
	defer cleanup()

	// Create and reconcile a Ready workload with filesystem overlay.
	wlReconciler := &WorkloadReconciler{
		Client: k8sClient,
		Scheme: k8sClient.Scheme(),
	}

	wl := &v1alpha1.BoilerhouseWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "overlay-wl",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseWorkloadSpec{
			Version: "1.0.0",
			Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
			Resources: v1alpha1.WorkloadResources{
				VCPUs:    1,
				MemoryMb: 256,
				DiskGb:   5,
			},
			Network: &v1alpha1.WorkloadNetwork{
				Expose: []v1alpha1.NetworkExposePort{{Guest: 8080}},
			},
			Filesystem: &v1alpha1.WorkloadFilesystem{
				OverlayDirs: []string{"/data"},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, wl))
	wlKey := types.NamespacedName{Name: "overlay-wl", Namespace: "default"}
	for i := 0; i < 3; i++ {
		_, err := wlReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: wlKey})
		require.NoError(t, err)
	}

	// Create a claim for tenant alice.
	claim := &v1alpha1.BoilerhouseClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "overlay-claim",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseClaimSpec{
			TenantId:    "alice",
			WorkloadRef: "overlay-wl",
		},
	}
	require.NoError(t, k8sClient.Create(ctx, claim))

	// Reconcile the claim (no SnapshotManager — snapshot injection is skipped).
	claimReconciler := &ClaimReconciler{
		Client:    k8sClient,
		Scheme:    k8sClient.Scheme(),
		Namespace: "default",
	}

	claimKey := types.NamespacedName{Name: "overlay-claim", Namespace: "default"}
	for i := 0; i < 5; i++ {
		_, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: claimKey})
		require.NoError(t, err)
		populateEmptyPodIPs(t, ctx, k8sClient, "default")
	}

	// Verify claim status: cold boot (no PVC check, snapshot injection
	// requires kubectl which is unavailable in envtest).
	var updatedClaim v1alpha1.BoilerhouseClaim
	require.NoError(t, k8sClient.Get(ctx, claimKey, &updatedClaim))
	assert.Equal(t, "Active", updatedClaim.Status.Phase)
	assert.Equal(t, "cold", updatedClaim.Status.Source)

	// Verify Pod has emptyDir volume for overlay.
	var podList corev1.PodList
	require.NoError(t, k8sClient.List(ctx, &podList,
		client.InNamespace("default"),
		client.MatchingLabels{
			LabelTenant:   "alice",
			LabelWorkload: "overlay-wl",
		},
	))
	require.Len(t, podList.Items, 1)
	pod := podList.Items[0]

	// Check that the Pod has an emptyDir volume.
	require.Len(t, pod.Spec.Volumes, 1)
	assert.Equal(t, "overlay-0", pod.Spec.Volumes[0].Name)
	assert.NotNil(t, pod.Spec.Volumes[0].EmptyDir)

	// Check that the container has a volume mount.
	require.NotEmpty(t, pod.Spec.Containers[0].VolumeMounts)
	assert.Equal(t, "/data", pod.Spec.Containers[0].VolumeMounts[0].MountPath)
}

func TestClaimController_ClaimFromPool(t *testing.T) {
	ctx, k8sClient, cleanup := setupEnvtest(t)
	defer cleanup()

	// Create and reconcile a Ready workload.
	wlReconciler := &WorkloadReconciler{
		Client: k8sClient,
		Scheme: k8sClient.Scheme(),
	}

	wl := &v1alpha1.BoilerhouseWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pool-claim-wl",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseWorkloadSpec{
			Version: "1.0.0",
			Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
			Resources: v1alpha1.WorkloadResources{
				VCPUs:    1,
				MemoryMb: 256,
				DiskGb:   5,
			},
			Network: &v1alpha1.WorkloadNetwork{
				Expose: []v1alpha1.NetworkExposePort{{Guest: 8080}},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, wl))
	wlKey := types.NamespacedName{Name: "pool-claim-wl", Namespace: "default"}
	for i := 0; i < 3; i++ {
		_, err := wlReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: wlKey})
		require.NoError(t, err)
	}

	// Create a pool Pod manually with pool-status=ready.
	poolPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pool-claim-wl-pool-abc123",
			Namespace: "default",
			Labels: map[string]string{
				LabelManaged:    "true",
				LabelWorkload:   "pool-claim-wl",
				LabelInstance:   "pool-claim-wl-pool-abc123",
				LabelPoolStatus: "ready",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "main",
					Image: "nginx:latest",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
					},
				},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, poolPod))

	// Patch the pool Pod to Running so it looks ready.
	poolPod.Status.Phase = corev1.PodRunning
	poolPod.Status.PodIP = "10.0.0.5"
	poolPod.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
	}
	require.NoError(t, k8sClient.Status().Update(ctx, poolPod))

	// Create a claim.
	claim := &v1alpha1.BoilerhouseClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pool-claim",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseClaimSpec{
			TenantId:    "bob",
			WorkloadRef: "pool-claim-wl",
		},
	}
	require.NoError(t, k8sClient.Create(ctx, claim))

	// Reconcile the claim.
	claimReconciler := &ClaimReconciler{
		Client:    k8sClient,
		Scheme:    k8sClient.Scheme(),
		Namespace: "default",
	}

	claimKey := types.NamespacedName{Name: "pool-claim", Namespace: "default"}
	for i := 0; i < 5; i++ {
		_, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: claimKey})
		require.NoError(t, err)
		populateEmptyPodIPs(t, ctx, k8sClient, "default")
	}

	// Verify claim status.
	var updatedClaim v1alpha1.BoilerhouseClaim
	require.NoError(t, k8sClient.Get(ctx, claimKey, &updatedClaim))
	assert.Equal(t, "Active", updatedClaim.Status.Phase)
	assert.Equal(t, "pool", updatedClaim.Status.Source)
	assert.Equal(t, "pool-claim-wl-pool-abc123", updatedClaim.Status.InstanceId)

	// Verify pool Pod was relabeled (tenant set, pool-status=acquired).
	var updatedPod corev1.Pod
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "pool-claim-wl-pool-abc123", Namespace: "default"}, &updatedPod))
	assert.Equal(t, "bob", updatedPod.Labels[LabelTenant])
	assert.Equal(t, "acquired", updatedPod.Labels[LabelPoolStatus])
}

func TestClaimController_ExistingInstance(t *testing.T) {
	ctx, k8sClient, cleanup := setupEnvtest(t)
	defer cleanup()

	// Create and reconcile a Ready workload.
	wlReconciler := &WorkloadReconciler{
		Client: k8sClient,
		Scheme: k8sClient.Scheme(),
	}

	wl := &v1alpha1.BoilerhouseWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-wl",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseWorkloadSpec{
			Version: "1.0.0",
			Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
			Resources: v1alpha1.WorkloadResources{
				VCPUs:    1,
				MemoryMb: 256,
				DiskGb:   5,
			},
			Network: &v1alpha1.WorkloadNetwork{
				Expose: []v1alpha1.NetworkExposePort{{Guest: 8080}},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, wl))
	wlKey := types.NamespacedName{Name: "existing-wl", Namespace: "default"}
	for i := 0; i < 3; i++ {
		_, err := wlReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: wlKey})
		require.NoError(t, err)
	}

	// Create an existing Pod with tenant label already running.
	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-wl-carol-existing",
			Namespace: "default",
			Labels: map[string]string{
				LabelManaged:  "true",
				LabelWorkload: "existing-wl",
				LabelInstance: "existing-wl-carol-existing",
				LabelTenant:   "carol",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "main",
					Image: "nginx:latest",
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
					},
				},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, existingPod))

	// Patch Pod to Running with an IP.
	existingPod.Status.Phase = corev1.PodRunning
	existingPod.Status.PodIP = "10.0.0.10"
	existingPod.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
	}
	require.NoError(t, k8sClient.Status().Update(ctx, existingPod))

	// Create a claim for the same tenant.
	claim := &v1alpha1.BoilerhouseClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-claim",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseClaimSpec{
			TenantId:    "carol",
			WorkloadRef: "existing-wl",
		},
	}
	require.NoError(t, k8sClient.Create(ctx, claim))

	// Reconcile the claim.
	claimReconciler := &ClaimReconciler{
		Client:    k8sClient,
		Scheme:    k8sClient.Scheme(),
		Namespace: "default",
	}

	claimKey := types.NamespacedName{Name: "existing-claim", Namespace: "default"}
	for i := 0; i < 5; i++ {
		_, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: claimKey})
		require.NoError(t, err)
		populateEmptyPodIPs(t, ctx, k8sClient, "default")
	}

	// Verify claim status.
	var updatedClaim v1alpha1.BoilerhouseClaim
	require.NoError(t, k8sClient.Get(ctx, claimKey, &updatedClaim))
	assert.Equal(t, "Active", updatedClaim.Status.Phase)
	assert.Equal(t, "existing", updatedClaim.Status.Source)
	assert.Equal(t, "existing-wl-carol-existing", updatedClaim.Status.InstanceId)
	assert.Equal(t, "10.0.0.10", updatedClaim.Status.Endpoint.Host)
	assert.Equal(t, 8080, updatedClaim.Status.Endpoint.Port)

	// Verify no new Pod was created — still just the one.
	var podList corev1.PodList
	require.NoError(t, k8sClient.List(ctx, &podList,
		client.InNamespace("default"),
		client.MatchingLabels{
			LabelTenant:   "carol",
			LabelWorkload: "existing-wl",
		},
	))
	assert.Len(t, podList.Items, 1, "should reuse existing pod, not create a new one")
}

func TestClaimController_ReleaseDeletesPod(t *testing.T) {
	ctx, k8sClient, cleanup := setupEnvtest(t)
	defer cleanup()

	// Create and reconcile a Ready workload.
	wlReconciler := &WorkloadReconciler{
		Client: k8sClient,
		Scheme: k8sClient.Scheme(),
	}

	wl := &v1alpha1.BoilerhouseWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "release-wl",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseWorkloadSpec{
			Version: "1.0.0",
			Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
			Resources: v1alpha1.WorkloadResources{
				VCPUs:    1,
				MemoryMb: 256,
				DiskGb:   5,
			},
			Network: &v1alpha1.WorkloadNetwork{
				Expose: []v1alpha1.NetworkExposePort{{Guest: 8080}},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, wl))
	wlKey := types.NamespacedName{Name: "release-wl", Namespace: "default"}
	for i := 0; i < 3; i++ {
		_, err := wlReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: wlKey})
		require.NoError(t, err)
	}

	// Create a claim and reconcile it to Active (cold boot).
	claim := &v1alpha1.BoilerhouseClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "release-claim",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseClaimSpec{
			TenantId:    "dave",
			WorkloadRef: "release-wl",
		},
	}
	require.NoError(t, k8sClient.Create(ctx, claim))

	claimReconciler := &ClaimReconciler{
		Client:    k8sClient,
		Scheme:    k8sClient.Scheme(),
		Namespace: "default",
	}

	// Reconcile to Active.
	claimKey := types.NamespacedName{Name: "release-claim", Namespace: "default"}
	for i := 0; i < 5; i++ {
		_, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: claimKey})
		require.NoError(t, err)
		populateEmptyPodIPs(t, ctx, k8sClient, "default")
	}

	// Verify Pod exists.
	var podList corev1.PodList
	require.NoError(t, k8sClient.List(ctx, &podList,
		client.InNamespace("default"),
		client.MatchingLabels{
			LabelTenant:   "dave",
			LabelWorkload: "release-wl",
		},
	))
	require.Len(t, podList.Items, 1)

	// Delete the claim (triggers finalizer flow).
	var latestClaim v1alpha1.BoilerhouseClaim
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "release-claim", Namespace: "default"}, &latestClaim))
	require.NoError(t, k8sClient.Delete(ctx, &latestClaim))

	// Reconcile the deletion.
	result, err := claimReconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "release-claim", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify Pod is deleted.
	var remainingPods corev1.PodList
	require.NoError(t, k8sClient.List(ctx, &remainingPods,
		client.InNamespace("default"),
		client.MatchingLabels{
			LabelTenant:   "dave",
			LabelWorkload: "release-wl",
		},
	))
	assert.Empty(t, remainingPods.Items, "pod should be deleted after claim deletion")

	// Verify claim is fully deleted (finalizer removed).
	var deletedClaim v1alpha1.BoilerhouseClaim
	err = k8sClient.Get(ctx, types.NamespacedName{Name: "release-claim", Namespace: "default"}, &deletedClaim)
	assert.Error(t, err, "claim should be deleted after finalizer removal")
}

func TestClaimController_WorkloadNotFoundError(t *testing.T) {
	ctx, k8sClient, cleanup := setupEnvtest(t)
	defer cleanup()

	// Create a claim referencing a non-existent workload.
	claim := &v1alpha1.BoilerhouseClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "orphan-claim",
			Namespace: "default",
		},
		Spec: v1alpha1.BoilerhouseClaimSpec{
			TenantId:    "eve",
			WorkloadRef: "does-not-exist",
		},
	}
	require.NoError(t, k8sClient.Create(ctx, claim))

	claimReconciler := &ClaimReconciler{
		Client:    k8sClient,
		Scheme:    k8sClient.Scheme(),
		Namespace: "default",
	}

	claimKey := types.NamespacedName{Name: "orphan-claim", Namespace: "default"}
	for i := 0; i < 5; i++ {
		_, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: claimKey})
		require.NoError(t, err)
		populateEmptyPodIPs(t, ctx, k8sClient, "default")
	}

	// Verify claim phase=Error.
	var updatedClaim v1alpha1.BoilerhouseClaim
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "orphan-claim", Namespace: "default"}, &updatedClaim))
	assert.Equal(t, "Error", updatedClaim.Status.Phase)
	assert.Equal(t, "workload not found", updatedClaim.Status.Detail)
}

// TestClaimController_HealsPendingPodMissingTokenSecret is a regression test for
// the resume deadlock: a Pod can be stuck Pending waiting on a token Secret that
// was GC'd with a prior claim generation, and the existing-Pod branch requeues
// forever without ever provisioning the token (only coldBoot did). handleNewClaim
// now ensures the token Secret on every reconcile, so the Secret appears and the
// stuck Pod can start.
func TestClaimController_HealsPendingPodMissingTokenSecret(t *testing.T) {
	ctx, k8sClient, cleanup := setupEnvtest(t)
	defer cleanup()

	wlReconciler := &WorkloadReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	wl := &v1alpha1.BoilerhouseWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: "heal-wl", Namespace: "default"},
		Spec: v1alpha1.BoilerhouseWorkloadSpec{
			Version: "1.0.0", Image: v1alpha1.WorkloadImage{Ref: "nginx:latest"},
			Resources: v1alpha1.WorkloadResources{VCPUs: 1, MemoryMb: 256, DiskGb: 5},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, wl))
	wlKey := types.NamespacedName{Name: "heal-wl", Namespace: "default"}
	for i := 0; i < 3; i++ {
		_, err := wlReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: wlKey})
		require.NoError(t, err)
	}

	// An existing tenant Pod that stays Pending (envtest has no kubelet) — stands
	// in for a Pod stuck on a missing token Secret.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "heal-wl-erin-x", Namespace: "default",
			Labels: map[string]string{
				LabelManaged: "true", LabelWorkload: "heal-wl",
				LabelInstance: "heal-wl-erin-x", LabelTenant: "erin",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "nginx:latest"}}},
	}
	require.NoError(t, k8sClient.Create(ctx, pod))

	claim := &v1alpha1.BoilerhouseClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "heal-claim", Namespace: "default"},
		Spec:       v1alpha1.BoilerhouseClaimSpec{TenantId: "erin", WorkloadRef: "heal-wl"},
	}
	require.NoError(t, k8sClient.Create(ctx, claim))

	secretKey := types.NamespacedName{Name: ClaimTokenSecretName("heal-claim"), Namespace: "default"}
	var pre corev1.Secret
	require.Error(t, k8sClient.Get(ctx, secretKey, &pre), "token secret must not exist before reconcile")

	claimReconciler := &ClaimReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), Namespace: "default"}
	claimKey := types.NamespacedName{Name: "heal-claim", Namespace: "default"}
	for i := 0; i < 5; i++ {
		_, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: claimKey})
		require.NoError(t, err)
	}

	// The heal: token Secret now exists even though the Pod is still Pending
	// (claim never reached Active — proving we provisioned outside coldBoot).
	var healed corev1.Secret
	require.NoError(t, k8sClient.Get(ctx, secretKey, &healed), "token secret should have been provisioned to heal the stuck Pod")
	assert.NotEmpty(t, healed.Data, "healed token secret must carry the token")
}
