package operator

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
)

// helper to create a RawExtension from a map of env vars.
func envRaw(m map[string]string) *runtime.RawExtension {
	b, _ := json.Marshal(m)
	return &runtime.RawExtension{Raw: b}
}

func TestTranslate_MinimalWorkload(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 512,
			DiskGb:   10,
		},
		Network: &v1alpha1.WorkloadNetwork{
			Access: "none",
		},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-001",
		WorkloadName: "my-workload",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	// Pod created with correct image and labels
	require.NotNil(t, result.Pod)
	assert.Equal(t, "inst-001", result.Pod.Name)
	assert.Equal(t, "default", result.Pod.Namespace)
	assert.Equal(t, "true", result.Pod.Labels["boilerhouse.dev/managed"])
	assert.Equal(t, "my-workload", result.Pod.Labels["boilerhouse.dev/workload"])
	assert.Equal(t, "inst-001", result.Pod.Labels["boilerhouse.dev/instance"])

	// No tenant label
	_, hasTenant := result.Pod.Labels["boilerhouse.dev/tenant"]
	assert.False(t, hasTenant)

	// No pool-status label
	_, hasPool := result.Pod.Labels["boilerhouse.dev/pool-status"]
	assert.False(t, hasPool)

	// Container image
	require.Len(t, result.Pod.Spec.Containers, 1)
	assert.Equal(t, "nginx:latest", result.Pod.Spec.Containers[0].Image)
	assert.Equal(t, "main", result.Pod.Spec.Containers[0].Name)

	// Security context: an agent sandbox allows privilege escalation (sudo/apt)
	// and keeps the default capability set; egress isolation comes from the pod's
	// iptables+envoy sidecar, not from dropping caps on the main container.
	sc := result.Pod.Spec.Containers[0].SecurityContext
	require.NotNil(t, sc)
	require.NotNil(t, sc.AllowPrivilegeEscalation)
	assert.True(t, *sc.AllowPrivilegeEscalation)
	assert.Nil(t, sc.Capabilities, "box main container should keep the default cap set (no drop-ALL)")

	// Pod-level seccomp profile
	require.NotNil(t, result.Pod.Spec.SecurityContext)
	require.NotNil(t, result.Pod.Spec.SecurityContext.SeccompProfile)
	assert.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, result.Pod.Spec.SecurityContext.SeccompProfile.Type)

	// Karpenter must not consolidation-evict a working box mid-task.
	assert.Equal(t, "true", result.Pod.Annotations["karpenter.sh/do-not-disrupt"])

	// restartPolicy, automountServiceAccountToken, terminationGracePeriodSeconds
	assert.Equal(t, corev1.RestartPolicyNever, result.Pod.Spec.RestartPolicy)
	require.NotNil(t, result.Pod.Spec.AutomountServiceAccountToken)
	assert.False(t, *result.Pod.Spec.AutomountServiceAccountToken)
	require.NotNil(t, result.Pod.Spec.TerminationGracePeriodSeconds)
	assert.Equal(t, int64(3), *result.Pod.Spec.TerminationGracePeriodSeconds)

	// NetworkPolicy denies all egress
	require.NotNil(t, result.NetworkPolicy)
	assert.Equal(t, "inst-001", result.NetworkPolicy.Name)
	assert.Empty(t, result.NetworkPolicy.Spec.Egress)
	assert.Contains(t, result.NetworkPolicy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)

	// No Service
	assert.Nil(t, result.Service)

	// ConfigMap nil for now
	assert.Nil(t, result.ConfigMap)
}

func TestTranslate_WorkloadWithOverlayDirs(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 512,
			DiskGb:   20,
		},
		Filesystem: &v1alpha1.WorkloadFilesystem{
			OverlayDirs: []string{"/data", "/config"},
		},
		Network: &v1alpha1.WorkloadNetwork{Access: "none"},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-002",
		WorkloadName: "overlay-wl",
		TenantId:     "tenant-abc",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	// Overlay dirs use emptyDir volumes (no PVC).
	container := result.Pod.Spec.Containers[0]
	require.Len(t, container.VolumeMounts, 2)
	assert.Equal(t, "/data", container.VolumeMounts[0].MountPath)
	assert.Equal(t, "overlay-0", container.VolumeMounts[0].Name)
	assert.Equal(t, "/config", container.VolumeMounts[1].MountPath)
	assert.Equal(t, "overlay-1", container.VolumeMounts[1].Name)

	// Pod has emptyDir volumes (one per overlay dir).
	require.Len(t, result.Pod.Spec.Volumes, 2)
	assert.Equal(t, "overlay-0", result.Pod.Spec.Volumes[0].Name)
	assert.NotNil(t, result.Pod.Spec.Volumes[0].EmptyDir)
	assert.Equal(t, "overlay-1", result.Pod.Spec.Volumes[1].Name)
	assert.NotNil(t, result.Pod.Spec.Volumes[1].EmptyDir)

	// Tenant label set
	assert.Equal(t, "tenant-abc", result.Pod.Labels["boilerhouse.dev/tenant"])
}

func TestTranslate_WorkloadWithExposedPorts(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "myapp:v2"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 256,
			DiskGb:   5,
		},
		Network: &v1alpha1.WorkloadNetwork{
			Access: "none",
			Expose: []v1alpha1.NetworkExposePort{{Guest: 8080}},
		},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-003",
		WorkloadName: "web-app",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	// Service created
	require.NotNil(t, result.Service)
	assert.Equal(t, "inst-003", result.Service.Name)
	assert.Equal(t, "default", result.Service.Namespace)
	require.Len(t, result.Service.Spec.Ports, 1)
	assert.Equal(t, int32(8080), result.Service.Spec.Ports[0].Port)
	assert.Equal(t, int32(8080), result.Service.Spec.Ports[0].TargetPort.IntVal)
	assert.Equal(t, corev1.ProtocolTCP, result.Service.Spec.Ports[0].Protocol)

	// Service selector
	assert.Equal(t, "inst-003", result.Service.Spec.Selector["boilerhouse.dev/instance"])

	// Pod has containerPort
	container := result.Pod.Spec.Containers[0]
	require.Len(t, container.Ports, 1)
	assert.Equal(t, int32(8080), container.Ports[0].ContainerPort)
	assert.Equal(t, corev1.ProtocolTCP, container.Ports[0].Protocol)
}

func TestTranslate_RestrictedNetworkPolicy(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 256,
			DiskGb:   5,
		},
		Network: &v1alpha1.WorkloadNetwork{
			Access: "restricted",
		},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-004",
		WorkloadName: "restricted-wl",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	np := result.NetworkPolicy
	require.NotNil(t, np)

	// PolicyTypes includes Egress
	assert.Contains(t, np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)

	// Two egress rules: DNS + HTTPS
	require.Len(t, np.Spec.Egress, 2)

	// Rule 0: DNS (UDP 53 + TCP 53)
	dnsRule := np.Spec.Egress[0]
	require.Len(t, dnsRule.Ports, 2)
	assert.Equal(t, 53, dnsRule.Ports[0].Port.IntValue())
	assert.Equal(t, 53, dnsRule.Ports[1].Port.IntValue())

	// Rule 1: HTTPS (TCP 443), blocks link-local
	httpsRule := np.Spec.Egress[1]
	require.Len(t, httpsRule.Ports, 1)
	assert.Equal(t, 443, httpsRule.Ports[0].Port.IntValue())
	require.Len(t, httpsRule.To, 1)
	require.NotNil(t, httpsRule.To[0].IPBlock)
	assert.Equal(t, "0.0.0.0/0", httpsRule.To[0].IPBlock.CIDR)
	assert.Contains(t, httpsRule.To[0].IPBlock.Except, "169.254.0.0/16")
}

func TestTranslate_UnrestrictedNetworkPolicy(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 256,
			DiskGb:   5,
		},
		Network: &v1alpha1.WorkloadNetwork{
			Access: "unrestricted",
		},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-005",
		WorkloadName: "unrestricted-wl",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	np := result.NetworkPolicy
	require.NotNil(t, np)

	// Two egress rules: DNS + all-except-link-local
	require.Len(t, np.Spec.Egress, 2)

	// Rule 0: DNS
	dnsRule := np.Spec.Egress[0]
	require.Len(t, dnsRule.Ports, 2)

	// Rule 1: All traffic except link-local (no port restriction)
	allRule := np.Spec.Egress[1]
	assert.Empty(t, allRule.Ports) // no port restriction
	require.Len(t, allRule.To, 1)
	require.NotNil(t, allRule.To[0].IPBlock)
	assert.Equal(t, "0.0.0.0/0", allRule.To[0].IPBlock.CIDR)
	assert.Contains(t, allRule.To[0].IPBlock.Except, "169.254.0.0/16")
}

func TestTranslate_HealthProbe(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "myapp:v1"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 256,
			DiskGb:   5,
		},
		Network: &v1alpha1.WorkloadNetwork{Access: "none"},
		Health: &v1alpha1.WorkloadHealth{
			IntervalSeconds:    10,
			UnhealthyThreshold: 3,
			HTTPGet: &v1alpha1.HealthHTTPGet{
				Path: "/healthz",
				Port: 8080,
			},
		},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-006",
		WorkloadName: "health-wl",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	probe := result.Pod.Spec.Containers[0].ReadinessProbe
	require.NotNil(t, probe)
	require.NotNil(t, probe.HTTPGet)
	assert.Equal(t, "/healthz", probe.HTTPGet.Path)
	assert.Equal(t, int32(8080), probe.HTTPGet.Port.IntVal)
	assert.Equal(t, int32(10), probe.PeriodSeconds)
	assert.Equal(t, int32(3), probe.FailureThreshold)
}

func TestTranslate_ExecHealthProbe(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "myapp:v1"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 256,
			DiskGb:   5,
		},
		Network: &v1alpha1.WorkloadNetwork{Access: "none"},
		Health: &v1alpha1.WorkloadHealth{
			IntervalSeconds:    5,
			UnhealthyThreshold: 2,
			Exec: &v1alpha1.HealthExec{
				Command: []string{"/bin/sh", "-c", "curl -f http://localhost:8080"},
			},
		},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-007",
		WorkloadName: "exec-health-wl",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	probe := result.Pod.Spec.Containers[0].ReadinessProbe
	require.NotNil(t, probe)
	require.NotNil(t, probe.Exec)
	assert.Equal(t, []string{"/bin/sh", "-c", "curl -f http://localhost:8080"}, probe.Exec.Command)
	assert.Equal(t, int32(5), probe.PeriodSeconds)
	assert.Equal(t, int32(2), probe.FailureThreshold)
	assert.Nil(t, probe.HTTPGet)
}

func TestTranslate_Entrypoint(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "myapp:v1"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 256,
			DiskGb:   5,
		},
		Network: &v1alpha1.WorkloadNetwork{Access: "none"},
		Entrypoint: &v1alpha1.WorkloadEntrypoint{
			Cmd:     "/bin/server",
			Args:    []string{"--port", "8080"},
			Workdir: "/app",
			Env:     envRaw(map[string]string{"NODE_ENV": "production", "PORT": "8080"}),
		},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-008",
		WorkloadName: "entrypoint-wl",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	container := result.Pod.Spec.Containers[0]
	assert.Equal(t, []string{"/bin/server"}, container.Command)
	assert.Equal(t, []string{"--port", "8080"}, container.Args)
	assert.Equal(t, "/app", container.WorkingDir)

	// Env vars - check both exist
	require.Len(t, container.Env, 2)
	envMap := map[string]string{}
	for _, e := range container.Env {
		envMap[e.Name] = e.Value
	}
	assert.Equal(t, "production", envMap["NODE_ENV"])
	assert.Equal(t, "8080", envMap["PORT"])
}

func TestTranslate_ClaimEnvOverridesAndReservedWins(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version:   "1.0.0",
		Image:     v1alpha1.WorkloadImage{Ref: "myapp:v1"},
		Resources: v1alpha1.WorkloadResources{VCPUs: 1, MemoryMb: 256, DiskGb: 5},
		Network:   &v1alpha1.WorkloadNetwork{Access: "restricted"},
		Entrypoint: &v1alpha1.WorkloadEntrypoint{
			Env: envRaw(map[string]string{"SHARED": "workload", "KEEP": "yes"}),
		},
	}
	opts := TranslateOpts{
		InstanceId:       "inst-claimenv",
		WorkloadName:     "claimenv-wl",
		Namespace:        "default",
		ClaimTokenSecret: "claim-key-x",
		APIServiceURL:    "http://boilerhouse-api.svc:8080",
		ClaimEnv: map[string]string{
			"SHARED":               "claim",       // overrides the workload value
			"CORDLESS_AGENT_TOKEN": "tok-123",     // new per-claim var
			"BOILERHOUSE_API_URL":  "http://evil", // reserved — must be dropped
		},
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	env := map[string]string{}
	for _, e := range result.Pod.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	assert.Equal(t, "claim", env["SHARED"], "claim env overrides workload env on a key clash")
	assert.Equal(t, "yes", env["KEEP"], "untouched workload env is preserved")
	assert.Equal(t, "tok-123", env["CORDLESS_AGENT_TOKEN"], "new per-claim var is injected")
	assert.Equal(t, "http://boilerhouse-api.svc:8080", env["BOILERHOUSE_API_URL"],
		"reserved bootstrap var wins over a claim-supplied BOILERHOUSE_* key")
}

func TestTranslate_PoolPod(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 256,
			DiskGb:   5,
		},
		Filesystem: &v1alpha1.WorkloadFilesystem{
			OverlayDirs: []string{"/data"},
		},
		Network: &v1alpha1.WorkloadNetwork{Access: "none"},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-009",
		WorkloadName: "pool-wl",
		Namespace:    "default",
		PoolStatus:   "warming",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	// Pool status label set
	assert.Equal(t, "warming", result.Pod.Labels["boilerhouse.dev/pool-status"])

	// No tenant label
	_, hasTenant := result.Pod.Labels["boilerhouse.dev/tenant"]
	assert.False(t, hasTenant)

	// Pool pods still get emptyDir volumes for overlay dirs.
	container := result.Pod.Spec.Containers[0]
	require.Len(t, container.VolumeMounts, 1)
	assert.Equal(t, "/data", container.VolumeMounts[0].MountPath)
	assert.Equal(t, "overlay-0", container.VolumeMounts[0].Name)
	require.Len(t, result.Pod.Spec.Volumes, 1)
	assert.NotNil(t, result.Pod.Spec.Volumes[0].EmptyDir)
}

func TestTranslate_ResourceLimits(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "heavy:latest"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    2,
			MemoryMb: 4096,
			DiskGb:   50,
		},
		Network: &v1alpha1.WorkloadNetwork{Access: "none"},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-010",
		WorkloadName: "heavy-wl",
		Namespace:    "default",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	resources := result.Pod.Spec.Containers[0].Resources

	// Request == limit for Guaranteed QoS: 2000m CPU, 4096Mi memory.
	cpuLimit := resources.Limits[corev1.ResourceCPU]
	assert.Equal(t, resource.MustParse("2000m"), cpuLimit)

	memLimit := resources.Limits[corev1.ResourceMemory]
	assert.Equal(t, resource.MustParse("4096Mi"), memLimit)

	cpuReq := resources.Requests[corev1.ResourceCPU]
	assert.Equal(t, resource.MustParse("2000m"), cpuReq)

	memReq := resources.Requests[corev1.ResourceMemory]
	assert.Equal(t, resource.MustParse("4096Mi"), memReq)
}

func TestTranslate_InjectsAPIKeyEnvWhenClaimTokenSecretSet(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version:   "1.0.0",
		Image:     v1alpha1.WorkloadImage{Ref: "nginx:latest"},
		Resources: v1alpha1.WorkloadResources{VCPUs: 1, MemoryMb: 256, DiskGb: 10},
		Network:   &v1alpha1.WorkloadNetwork{Access: "none"},
		Entrypoint: &v1alpha1.WorkloadEntrypoint{
			Env: envRaw(map[string]string{"FOO": "bar"}),
		},
	}
	opts := TranslateOpts{
		InstanceId:       "inst-tok",
		WorkloadName:     "wl-tok",
		Namespace:        "boilerhouse",
		ClaimTokenSecret: "claim-key-my-claim",
		APIServiceURL:    "http://boilerhouse-api.boilerhouse.svc:3000",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	env := result.Pod.Spec.Containers[0].Env
	var foundKey, foundURL bool
	for _, e := range env {
		switch e.Name {
		case "BOILERHOUSE_API_KEY":
			require.NotNil(t, e.ValueFrom)
			require.NotNil(t, e.ValueFrom.SecretKeyRef)
			assert.Equal(t, "claim-key-my-claim", e.ValueFrom.SecretKeyRef.Name)
			assert.Equal(t, "token", e.ValueFrom.SecretKeyRef.Key)
			foundKey = true
		case "BOILERHOUSE_API_URL":
			assert.Equal(t, "http://boilerhouse-api.boilerhouse.svc:3000", e.Value)
			foundURL = true
		}
	}
	assert.True(t, foundKey, "BOILERHOUSE_API_KEY env not injected")
	assert.True(t, foundURL, "BOILERHOUSE_API_URL env not injected")

	// Pre-existing env var from the workload must still be present.
	var foundFoo bool
	for _, e := range env {
		if e.Name == "FOO" && e.Value == "bar" {
			foundFoo = true
		}
	}
	assert.True(t, foundFoo, "workload env var FOO was dropped")
}

func TestTranslate_NoAPIKeyEnvWhenClaimTokenSecretUnset(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version:   "1.0.0",
		Image:     v1alpha1.WorkloadImage{Ref: "nginx:latest"},
		Resources: v1alpha1.WorkloadResources{VCPUs: 1, MemoryMb: 256, DiskGb: 10},
		Network:   &v1alpha1.WorkloadNetwork{Access: "none"},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-notok",
		WorkloadName: "wl-notok",
		Namespace:    "boilerhouse",
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	for _, e := range result.Pod.Spec.Containers[0].Env {
		assert.NotEqual(t, "BOILERHOUSE_API_KEY", e.Name)
		assert.NotEqual(t, "BOILERHOUSE_API_URL", e.Name)
	}
}

// With the egress sidecar present (ProxyConfig set), restricted egress also
// opens :80 — Envoy forwards allowlisted plain-HTTP upstream on 80 (in-cluster
// control planes, package mirrors) and enforces the per-destination allowlist
// itself; the NetworkPolicy is the outer belt. Sidecar-less restricted keeps
// the tighter 443-only posture (covered by TestTranslate_RestrictedNetworkPolicy).
func TestTranslate_RestrictedNetworkPolicyWithSidecarOpensHTTP(t *testing.T) {
	spec := v1alpha1.BoilerhouseWorkloadSpec{
		Version: "1.0.0",
		Image:   v1alpha1.WorkloadImage{Ref: "nginx:latest"},
		Resources: v1alpha1.WorkloadResources{
			VCPUs:    1,
			MemoryMb: 256,
			DiskGb:   5,
		},
		Network: &v1alpha1.WorkloadNetwork{
			Access: "restricted",
		},
	}
	opts := TranslateOpts{
		InstanceId:   "inst-005",
		WorkloadName: "restricted-proxied-wl",
		Namespace:    "default",
		ProxyConfig:  &ProxyConfig{EnvoyYAML: "yaml"},
	}

	result, err := Translate(spec, opts)
	require.NoError(t, err)

	np := result.NetworkPolicy
	require.NotNil(t, np)
	require.Len(t, np.Spec.Egress, 2)

	rule := np.Spec.Egress[1]
	require.Len(t, rule.Ports, 2)
	assert.Equal(t, 443, rule.Ports[0].Port.IntValue())
	assert.Equal(t, 80, rule.Ports[1].Port.IntValue())
}
