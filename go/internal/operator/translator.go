package operator

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/zdavison/boilerhouse/go/internal/envoy"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	LabelManaged    = "boilerhouse.dev/managed"
	LabelWorkload   = "boilerhouse.dev/workload"
	LabelInstance   = "boilerhouse.dev/instance"
	LabelTenant     = "boilerhouse.dev/tenant"
	LabelPoolStatus = "boilerhouse.dev/pool-status"

	linkLocalCIDR = "169.254.0.0/16"
)

// TranslateOpts holds the metadata needed to translate a workload spec into
// Kubernetes resources.
type TranslateOpts struct {
	InstanceId       string
	WorkloadName     string
	TenantId         string // empty for pool pods
	Namespace        string
	PoolStatus       string            // "warming", "ready", or "" for non-pool
	ImageRef         string            // resolved image reference (handles dockerfile builds)
	ProxyConfig      *ProxyConfig      // nil if no sidecar needed
	ClaimTokenSecret string            // name of Secret holding the scoped API token; empty = no token injection
	APIServiceURL    string            // in-cluster URL of the Boilerhouse API; required when ClaimTokenSecret is set
	ClaimEnv         map[string]string // optional per-claim env, merged over workload env (reserved BOILERHOUSE_* always win)
}

// TranslateResult holds the Kubernetes resources produced by Translate.
type TranslateResult struct {
	Pod           *corev1.Pod
	Service       *corev1.Service
	NetworkPolicy *networkingv1.NetworkPolicy
	ConfigMap     *corev1.ConfigMap // for Envoy sidecar proxy config
}

// Translate converts a BoilerhouseWorkloadSpec and metadata into Kubernetes
// resource specs: Pod, optional Service, NetworkPolicy, and optional PVC.
func Translate(spec v1alpha1.BoilerhouseWorkloadSpec, opts TranslateOpts) (*TranslateResult, error) {
	result := &TranslateResult{}

	labels := buildLabels(opts)

	pod, err := buildPod(spec, opts, labels)
	if err != nil {
		return nil, fmt.Errorf("building pod: %w", err)
	}
	result.Pod = pod

	if spec.Network != nil && len(spec.Network.Expose) > 0 {
		result.Service = buildService(spec, opts, labels)
	}

	result.NetworkPolicy = buildNetworkPolicy(spec, opts, labels)

	// PVC creation removed: overlay persistence now uses snapshot-based approach.
	// Overlay dirs use emptyDir volumes in the Pod spec (see buildPod).

	// Inject Envoy sidecar if ProxyConfig is provided.
	if opts.ProxyConfig != nil {
		configMapName := fmt.Sprintf("proxy-%s", opts.InstanceId)
		InjectSidecar(result.Pod, configMapName)
		result.ConfigMap = buildProxyConfigMap(opts, labels, configMapName)
	}

	return result, nil
}

func buildLabels(opts TranslateOpts) map[string]string {
	labels := map[string]string{
		LabelManaged:  "true",
		LabelWorkload: opts.WorkloadName,
		LabelInstance: opts.InstanceId,
	}
	if opts.TenantId != "" {
		labels[LabelTenant] = opts.TenantId
	}
	if opts.PoolStatus != "" {
		labels[LabelPoolStatus] = opts.PoolStatus
	}
	return labels
}

func buildPod(spec v1alpha1.BoilerhouseWorkloadSpec, opts TranslateOpts, labels map[string]string) (*corev1.Pod, error) {
	falseVal := false
	terminationGrace := int64(3)

	container, err := buildContainer(spec, opts)
	if err != nil {
		return nil, err
	}

	// Hardened default pod security context; a workload may additionally pin
	// runAsUser/runAsGroup/fsGroup/runAsNonRoot via spec.Security (e.g. so a
	// non-root image can own its mounted overlay volumes).
	podSec := &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
	if spec.Security != nil {
		podSec.RunAsUser = spec.Security.RunAsUser
		podSec.RunAsGroup = spec.Security.RunAsGroup
		podSec.FSGroup = spec.Security.FsGroup
		podSec.RunAsNonRoot = spec.Security.RunAsNonRoot
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.InstanceId,
			Namespace: opts.Namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers:                    []corev1.Container{*container},
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  &falseVal,
			TerminationGracePeriodSeconds: &terminationGrace,
			SecurityContext:               podSec,
		},
	}

	// Overlay volume mounts: use emptyDir volumes for all overlay dirs.
	// Persistence is handled by the snapshot manager (tar extract/inject),
	// not per-tenant PVCs.
	if spec.Filesystem != nil && len(spec.Filesystem.OverlayDirs) > 0 {
		var volumes []corev1.Volume
		var mounts []corev1.VolumeMount
		for i, dir := range spec.Filesystem.OverlayDirs {
			volName := fmt.Sprintf("overlay-%d", i)
			volumes = append(volumes, corev1.Volume{
				Name: volName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			})
			mounts = append(mounts, corev1.VolumeMount{
				Name:      volName,
				MountPath: dir,
			})
		}
		pod.Spec.Volumes = append(pod.Spec.Volumes, volumes...)
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, mounts...)
	}

	return pod, nil
}

func buildContainer(spec v1alpha1.BoilerhouseWorkloadSpec, opts TranslateOpts) (*corev1.Container, error) {
	falseVal := false

	imageRef := opts.ImageRef
	if imageRef == "" {
		imageRef = spec.Image.Ref
	}

	pullPolicy := corev1.PullIfNotPresent
	if spec.Image.Dockerfile != "" {
		pullPolicy = corev1.PullNever
	}

	container := &corev1.Container{
		Name:            "main",
		Image:           imageRef,
		ImagePullPolicy: pullPolicy,
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
			AllowPrivilegeEscalation: &falseVal,
		},
	}

	// Resources — request == limit gives the pod Guaranteed QoS. With the
	// previous burstable sizing (CPU request = 25% of limit, memory request
	// capped at 128Mi) large pods would be binpacked on nodes that couldn't
	// actually fulfil their limits and OOMKilled under pressure. Tenants
	// state what they need via spec.Resources; we honour that verbatim.
	cpuMillis := spec.Resources.VCPUs * 1000
	memMi := spec.Resources.MemoryMb

	container.Resources = corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%dm", cpuMillis)),
			corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", memMi)),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%dm", cpuMillis)),
			corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", memMi)),
		},
	}

	// Entrypoint
	if spec.Entrypoint != nil {
		if spec.Entrypoint.Cmd != "" {
			container.Command = []string{spec.Entrypoint.Cmd}
		}
		if len(spec.Entrypoint.Args) > 0 {
			container.Args = spec.Entrypoint.Args
		}
		if spec.Entrypoint.Workdir != "" {
			container.WorkingDir = spec.Entrypoint.Workdir
		}
		if spec.Entrypoint.Env != nil && spec.Entrypoint.Env.Raw != nil {
			envVars, err := parseEnvVars(spec.Entrypoint.Env.Raw)
			if err != nil {
				return nil, fmt.Errorf("parsing env vars: %w", err)
			}
			container.Env = envVars
		}
	}

	// Per-claim env overrides workload entrypoint env on a key clash. The
	// reserved BOILERHOUSE_* bootstrap vars are appended afterwards and always win.
	if len(opts.ClaimEnv) > 0 {
		container.Env = mergeEnv(container.Env, opts.ClaimEnv)
	}

	if opts.ClaimTokenSecret != "" {
		container.Env = append(container.Env,
			corev1.EnvVar{
				Name: "BOILERHOUSE_API_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: opts.ClaimTokenSecret},
						Key:                  "token",
					},
				},
			},
			corev1.EnvVar{
				Name:  "BOILERHOUSE_API_URL",
				Value: opts.APIServiceURL,
			},
		)
	}

	// Exposed ports
	if spec.Network != nil {
		for _, p := range spec.Network.Expose {
			container.Ports = append(container.Ports, corev1.ContainerPort{
				ContainerPort: int32(p.Guest),
				Protocol:      corev1.ProtocolTCP,
			})
		}
	}

	// Health probe
	if spec.Health != nil {
		probe := &corev1.Probe{
			PeriodSeconds:    int32(spec.Health.IntervalSeconds),
			FailureThreshold: int32(spec.Health.UnhealthyThreshold),
		}
		if spec.Health.HTTPGet != nil {
			probe.ProbeHandler = corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: spec.Health.HTTPGet.Path,
					Port: intstr.FromInt32(int32(spec.Health.HTTPGet.Port)),
				},
			}
		} else if spec.Health.Exec != nil {
			probe.ProbeHandler = corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: spec.Health.Exec.Command,
				},
			}
		}
		container.ReadinessProbe = probe
	}

	return container, nil
}

// parseEnvVars decodes a JSON object of env vars (map[string]string) into
// a sorted slice of corev1.EnvVar.
func parseEnvVars(raw []byte) ([]corev1.EnvVar, error) {
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	// Sort keys for deterministic output.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	envVars := make([]corev1.EnvVar, 0, len(m))
	for _, k := range keys {
		envVars = append(envVars, corev1.EnvVar{
			Name:  k,
			Value: m[k],
		})
	}
	return envVars, nil
}

// mergeEnv overlays overlay onto base (overriding any EnvVar with the same
// name), dropping any reserved BOILERHOUSE_* keys from the overlay, and returns
// a deterministically name-sorted slice. base entries that are not overridden
// are preserved verbatim (including any ValueFrom sources).
func mergeEnv(base []corev1.EnvVar, overlay map[string]string) []corev1.EnvVar {
	merged := make(map[string]corev1.EnvVar, len(base)+len(overlay))
	names := make([]string, 0, len(base)+len(overlay))
	add := func(name string) {
		if _, seen := merged[name]; !seen {
			names = append(names, name)
		}
	}
	for _, e := range base {
		add(e.Name)
		merged[e.Name] = e
	}
	for k, v := range overlay {
		if strings.HasPrefix(k, "BOILERHOUSE_") {
			continue // reserved bootstrap namespace — never overridable by a claim
		}
		add(k)
		merged[k] = corev1.EnvVar{Name: k, Value: v}
	}
	sort.Strings(names)
	out := make([]corev1.EnvVar, 0, len(names))
	for _, name := range names {
		out = append(out, merged[name])
	}
	return out
}

func buildService(spec v1alpha1.BoilerhouseWorkloadSpec, opts TranslateOpts, labels map[string]string) *corev1.Service {
	var ports []corev1.ServicePort
	for i, p := range spec.Network.Expose {
		sp := corev1.ServicePort{
			Port:       int32(p.Guest),
			TargetPort: intstr.FromInt32(int32(p.Guest)),
			Protocol:   corev1.ProtocolTCP,
		}
		if len(spec.Network.Expose) > 1 {
			sp.Name = fmt.Sprintf("port-%d", i)
		}
		ports = append(ports, sp)
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.InstanceId,
			Namespace: opts.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				LabelInstance: opts.InstanceId,
			},
			Ports: ports,
			Type:  corev1.ServiceTypeClusterIP,
		},
	}
}

func buildNetworkPolicy(spec v1alpha1.BoilerhouseWorkloadSpec, opts TranslateOpts, labels map[string]string) *networkingv1.NetworkPolicy {
	access := "none"
	if spec.Network != nil && spec.Network.Access != "" {
		access = spec.Network.Access
	}

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.InstanceId,
			Namespace: opts.Namespace,
			Labels:    labels,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					LabelInstance: opts.InstanceId,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}

	switch access {
	case "unrestricted":
		np.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
			dnsEgressRule(),
			{
				To: []networkingv1.NetworkPolicyPeer{
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR:   "0.0.0.0/0",
							Except: []string{linkLocalCIDR},
						},
					},
				},
			},
		}
	case "restricted":
		np.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
			dnsEgressRule(),
			{
				Ports: []networkingv1.NetworkPolicyPort{
					networkPolicyPort(corev1.ProtocolTCP, 443),
				},
				To: []networkingv1.NetworkPolicyPeer{
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR:   "0.0.0.0/0",
							Except: []string{linkLocalCIDR},
						},
					},
				},
			},
		}
	default: // "none" — deny all egress
		np.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{}
	}

	return np
}

func dnsEgressRule() networkingv1.NetworkPolicyEgressRule {
	return networkingv1.NetworkPolicyEgressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			networkPolicyPort(corev1.ProtocolUDP, 53),
			networkPolicyPort(corev1.ProtocolTCP, 53),
		},
		To: []networkingv1.NetworkPolicyPeer{
			{NamespaceSelector: &metav1.LabelSelector{}},
		},
	}
}

func networkPolicyPort(protocol corev1.Protocol, port int) networkingv1.NetworkPolicyPort {
	p := intstr.FromInt32(int32(port))
	proto := protocol
	return networkingv1.NetworkPolicyPort{
		Protocol: &proto,
		Port:     &p,
	}
}

// buildProxyConfigMap creates a ConfigMap with the Envoy YAML config and CA cert
// for the sidecar proxy.
func buildProxyConfigMap(opts TranslateOpts, labels map[string]string, name string) *corev1.ConfigMap {
	data := map[string]string{
		"envoy.yaml": opts.ProxyConfig.EnvoyYAML,
	}
	if opts.ProxyConfig.CACert != nil {
		data["ca.crt"] = string(opts.ProxyConfig.CACert)
	}

	// Add per-domain TLS certs if TLS material is available.
	if opts.ProxyConfig.TLS != nil {
		for _, dc := range opts.ProxyConfig.TLS.Certs {
			safe := envoy.SafeDomain(dc.Domain)
			data[safe+".crt"] = string(dc.Cert)
			data[safe+".key"] = string(dc.Key)
		}
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: opts.Namespace,
			Labels:    labels,
		},
		Data: data,
	}
}
