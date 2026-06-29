package operator

import (
	"context"
	"fmt"

	"github.com/zdavison/boilerhouse/go/internal/envoy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
)

const (
	EnvoyImage = "docker.io/envoyproxy/envoy:v1.32-latest"
	// IPTablesImage is a minimal image used by the init container that
	// installs the NAT redirect rules directing pod outbound traffic
	// into envoy.
	IPTablesImage = "docker.io/alpine:3.21"
	// Non-privileged ports envoy listens on. Client traffic is transparently
	// redirected here by iptables NAT rules installed at pod startup.
	EnvoyProxyPort = 18080
	EnvoyTLSPort   = 18443
	EnvoyAdminPort = 18081
	// EnvoyRunAsUID is the uid envoy runs as (the default "envoy" user in
	// the envoyproxy image). iptables rules use this to exempt envoy's own
	// outbound traffic from the redirect — otherwise every upstream call
	// would loop back into envoy itself.
	EnvoyRunAsUID = int64(101)
)

// ProxyConfig holds pre-generated Envoy configuration and CA cert for sidecar injection.
type ProxyConfig struct {
	EnvoyYAML string // the generated Envoy bootstrap YAML
	CACert    []byte // PEM-encoded CA certificate for trust
	TLS       *envoy.TLSMaterial
}

// InjectSidecar modifies a Pod spec for transparent credential injection:
//
//   - An init container runs iptables and installs NAT rules redirecting
//     outbound ports 80/443 to envoy's listeners on 127.0.0.1:18080/18443.
//     The rules exempt envoy's own UID so envoy's upstream calls to the real
//     destination aren't caught by the redirect (without this exemption the
//     sidecar infinite-loops through itself).
//   - Envoy runs as uid 101 on 127.0.0.1 (no privileged ports, no caps).
//   - Main container trusts envoy's generated CA via NODE_EXTRA_CA_CERTS.
//
// Clients are unaware of the proxy — they connect to the real domain on
// standard ports; the kernel does the redirection.
func InjectSidecar(pod *corev1.Pod, configMapName string) {
	falseVal := false
	readOnly := true
	runAsEnvoy := EnvoyRunAsUID
	runAsRoot := int64(0)

	// 1. Init container: install iptables redirect rules.
	initContainer := corev1.Container{
		Name:    "iptables-init",
		Image:   IPTablesImage,
		Command: []string{"sh", "-c", buildIPTablesScript()},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("10m"),
				corev1.ResourceMemory: resource.MustParse("16Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
		},
		SecurityContext: &corev1.SecurityContext{
			// NET_ADMIN is required to modify netfilter rules. Init runs
			// as root (apk needs write access to /var/cache/apk).
			RunAsUser: &runAsRoot,
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				Add:  []corev1.Capability{"NET_ADMIN"},
			},
			AllowPrivilegeEscalation: &falseVal,
		},
	}
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, initContainer)

	// 2. Envoy sidecar: listens on loopback, runs as uid 101 (must match
	// iptables --uid-owner exemption). It is a NATIVE sidecar — an init container
	// with restartPolicy=Always + a startup probe — so the kernel redirect points
	// at a READY envoy before the main container starts. Otherwise the main
	// container's first egress (e.g. the agent reaching the LLM at boot) races
	// envoy coming up and gets connection-refused.
	alwaysRestart := corev1.ContainerRestartPolicyAlways
	envoyContainer := corev1.Container{
		Name:          "envoy",
		Image:         EnvoyImage,
		RestartPolicy: &alwaysRestart,
		StartupProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt(EnvoyTLSPort)},
			},
			PeriodSeconds:    1,
			FailureThreshold: 30, // up to ~30s for envoy to bind its listeners
		},
		Command: []string{"envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "warn"},
		Ports: []corev1.ContainerPort{
			{ContainerPort: int32(EnvoyProxyPort), Protocol: corev1.ProtocolTCP},
			{ContainerPort: int32(EnvoyTLSPort), Protocol: corev1.ProtocolTCP},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("50m"),
				corev1.ResourceMemory: resource.MustParse("32Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
		},
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: &runAsEnvoy,
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
			AllowPrivilegeEscalation: &falseVal,
			ReadOnlyRootFilesystem:   &readOnly,
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "proxy-config",
				MountPath: "/etc/envoy",
				ReadOnly:  true,
			},
		},
	}
	// Native sidecar → runs as an init container (after iptables-init) so it is
	// up + probed-ready before the main container starts.
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, envoyContainer)

	// 3. proxy-config volume (envoy YAML + CA cert + per-domain certs).
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: "proxy-config",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: configMapName,
				},
			},
		},
	})

	// 4. Main container: trust envoy's CA. No proxy env vars — iptables
	// handles the redirect transparently.
	if len(pod.Spec.Containers) > 0 {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name: "NODE_EXTRA_CA_CERTS", Value: "/etc/envoy/ca.crt",
		})
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      "proxy-config",
			MountPath: "/etc/envoy/ca.crt",
			SubPath:   "ca.crt",
			ReadOnly:  true,
		})
	}
}

// buildIPTablesScript returns the shell script run by the init container.
// The rules redirect outbound 80/443 into envoy, exempt envoy's own UID so
// envoy's upstream calls reach the real internet, and block the cloud
// metadata server (169.254.0.0/16) as a basic hardening measure.
func buildIPTablesScript() string {
	return fmt.Sprintf(
		`set -eu
apk add --no-cache -q iptables >/dev/null 2>&1
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
iptables -t nat -A OUTPUT -m owner --uid-owner %d -j RETURN
iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-port %d
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port %d
echo "iptables rules installed"
`,
		EnvoyRunAsUID, EnvoyProxyPort, EnvoyTLSPort,
	)
}

// ResolveCredentials resolves Secret references in workload credential headers.
// All secretKeyRefs resolve from Secrets in the operator's namespace.
func ResolveCredentials(ctx context.Context, k8sClient client.Client, namespace string, credentials []v1alpha1.NetworkCredential) ([]envoy.ResolvedCredential, error) {
	secretCache := map[string]map[string][]byte{}

	var resolved []envoy.ResolvedCredential
	for _, cred := range credentials {
		if cred.Domain == "" {
			continue
		}

		headers := make(map[string]string, len(cred.Headers))
		for _, h := range cred.Headers {
			if h.Name == "" {
				return nil, fmt.Errorf("credential for domain %s: header entry missing name", cred.Domain)
			}

			switch {
			case h.ValueFrom == nil && h.Value == "":
				return nil, fmt.Errorf("credential for domain %s: header %q has neither value nor valueFrom", cred.Domain, h.Name)
			case h.ValueFrom != nil && h.Value != "":
				return nil, fmt.Errorf("credential for domain %s: header %q sets both value and valueFrom", cred.Domain, h.Name)
			case h.ValueFrom != nil:
				v, err := resolveSecretKeyRef(ctx, k8sClient, namespace, h.ValueFrom.SecretKeyRef, secretCache)
				if err != nil {
					return nil, fmt.Errorf("credential for domain %s, header %q: %w", cred.Domain, h.Name, err)
				}
				headers[h.Name] = v
			default:
				headers[h.Name] = h.Value
			}
		}

		resolved = append(resolved, envoy.ResolvedCredential{Domain: cred.Domain, Headers: headers})
	}

	return resolved, nil
}

// resolveSecretKeyRef fetches (and caches) a Secret in the operator namespace
// and returns the value at ref.Key.
func resolveSecretKeyRef(ctx context.Context, k8sClient client.Client, namespace string, ref *v1alpha1.SecretKeyRef, cache map[string]map[string][]byte) (string, error) {
	if ref == nil {
		return "", fmt.Errorf("valueFrom.secretKeyRef is nil")
	}
	if ref.Name == "" || ref.Key == "" {
		return "", fmt.Errorf("secretKeyRef requires name and key")
	}

	data, ok := cache[ref.Name]
	if !ok {
		var secret corev1.Secret
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, &secret); err != nil {
			return "", fmt.Errorf("secret %q: %w", ref.Name, err)
		}
		data = secret.Data
		cache[ref.Name] = data
	}

	value, ok := data[ref.Key]
	if !ok {
		return "", fmt.Errorf("secret %q: key %q not found", ref.Name, ref.Key)
	}
	return string(value), nil
}
