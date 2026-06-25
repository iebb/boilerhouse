package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// WorkloadImage defines the container image for a workload.
// Exactly one of Ref or Dockerfile must be set.
type WorkloadImage struct {
	// Ref is a container image reference (e.g., alpine:3.19, ghcr.io/org/img:tag).
	// +optional
	Ref string `json:"ref,omitempty"`
	// Dockerfile is the path to a Dockerfile relative to the workloads directory.
	// When set, the operator builds the image and tags it as boilerhouse/<name>:<version>.
	// +optional
	Dockerfile string `json:"dockerfile,omitempty"`
}

// WorkloadResources defines resource requirements for a workload.
type WorkloadResources struct {
	// VCPUs is the number of virtual CPUs.
	VCPUs int `json:"vcpus"`
	// MemoryMb is the memory in megabytes.
	MemoryMb int `json:"memoryMb"`
	// DiskGb is the disk size in gigabytes.
	DiskGb int `json:"diskGb"`
}

// NetworkExposePort defines a guest port to expose.
type NetworkExposePort struct {
	// Guest is the port number inside the workload.
	// +optional
	Guest int `json:"guest,omitempty"`
}

// NetworkCredential defines credentials for a domain.
type NetworkCredential struct {
	// Domain is the domain to apply credentials to.
	// +optional
	Domain string `json:"domain,omitempty"`
	// Headers to inject on requests to Domain.
	// +optional
	Headers []HeaderEntry `json:"headers,omitempty"`
}

// HeaderEntry is one injected header. Exactly one of Value or ValueFrom must
// be set.
type HeaderEntry struct {
	// Name is the HTTP header name.
	Name string `json:"name"`
	// Value is a literal header value.
	// +optional
	Value string `json:"value,omitempty"`
	// ValueFrom sources the value from a Kubernetes Secret in the operator's
	// namespace.
	// +optional
	ValueFrom *HeaderValueSource `json:"valueFrom,omitempty"`
}

// HeaderValueSource describes how a header value is sourced.
type HeaderValueSource struct {
	// SecretKeyRef selects a key from a Secret in the operator's namespace.
	SecretKeyRef *SecretKeyRef `json:"secretKeyRef"`
}

// SecretKeyRef references a single key within a Kubernetes Secret.
type SecretKeyRef struct {
	// Name is the name of the Secret in the operator's namespace.
	Name string `json:"name"`
	// Key is the key within the Secret's data map.
	Key string `json:"key"`
}

// WorkloadNetwork defines network configuration for a workload.
type WorkloadNetwork struct {
	// Access controls the network access level.
	// +optional
	// +kubebuilder:validation:Enum=none;restricted;unrestricted
	Access string `json:"access,omitempty"`
	// Expose lists ports to expose from the workload.
	// +optional
	Expose []NetworkExposePort `json:"expose,omitempty"`
	// Allowlist defines allowed network destinations.
	// +optional
	Allowlist []string `json:"allowlist,omitempty"`
	// Credentials defines per-domain credentials.
	// +optional
	Credentials []NetworkCredential `json:"credentials,omitempty"`
	// Websocket configures WebSocket support.
	// +optional
	Websocket string `json:"websocket,omitempty"`
}

// WorkloadFilesystem defines filesystem configuration for a workload.
type WorkloadFilesystem struct {
	// OverlayDirs lists directories to overlay.
	// +optional
	OverlayDirs []string `json:"overlayDirs,omitempty"`
	// EncryptOverlays enables encryption of overlay directories.
	// +optional
	EncryptOverlays *bool `json:"encryptOverlays,omitempty"`
}

// WorkloadIdle defines idle behavior for a workload.
type WorkloadIdle struct {
	// TimeoutSeconds is the idle timeout in seconds.
	// +optional
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// Action is the action to take when idle.
	// +optional
	// +kubebuilder:validation:Enum=hibernate;destroy
	Action string `json:"action,omitempty"`
	// WatchDirs lists directories to watch for activity.
	// +optional
	WatchDirs []string `json:"watchDirs,omitempty"`
}

// HealthHTTPGet defines an HTTP health check.
type HealthHTTPGet struct {
	// Path is the HTTP path to check.
	// +optional
	Path string `json:"path,omitempty"`
	// Port is the port to check.
	// +optional
	Port int `json:"port,omitempty"`
}

// HealthExec defines a command-based health check.
type HealthExec struct {
	// Command is the command to execute.
	// +optional
	Command []string `json:"command,omitempty"`
}

// WorkloadHealth defines health check configuration for a workload.
type WorkloadHealth struct {
	// IntervalSeconds is the interval between health checks.
	// +optional
	IntervalSeconds int `json:"intervalSeconds,omitempty"`
	// UnhealthyThreshold is the number of failures before marking unhealthy.
	// +optional
	UnhealthyThreshold int `json:"unhealthyThreshold,omitempty"`
	// HTTPGet defines an HTTP health check.
	// +optional
	HTTPGet *HealthHTTPGet `json:"httpGet,omitempty"`
	// Exec defines a command-based health check.
	// +optional
	Exec *HealthExec `json:"exec,omitempty"`
}

// WorkloadEntrypoint defines the entrypoint for a workload.
type WorkloadEntrypoint struct {
	// Cmd is the command to run.
	// +optional
	Cmd string `json:"cmd,omitempty"`
	// Args is the list of arguments.
	// +optional
	Args []string `json:"args,omitempty"`
	// Env is a free-form map of environment variables.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Env *runtime.RawExtension `json:"env,omitempty"`
	// Workdir is the working directory.
	// +optional
	Workdir string `json:"workdir,omitempty"`
}

// BoilerhouseWorkloadSpec defines the desired state of a BoilerhouseWorkload.
type BoilerhouseWorkloadSpec struct {
	// Version is the workload version string.
	Version string `json:"version"`
	// Image defines the container image.
	Image WorkloadImage `json:"image"`
	// Resources defines resource requirements.
	Resources WorkloadResources `json:"resources"`
	// Network defines network configuration.
	// +optional
	Network *WorkloadNetwork `json:"network,omitempty"`
	// Filesystem defines filesystem configuration.
	// +optional
	Filesystem *WorkloadFilesystem `json:"filesystem,omitempty"`
	// Idle defines idle behavior.
	// +optional
	Idle *WorkloadIdle `json:"idle,omitempty"`
	// Health defines health check configuration.
	// +optional
	Health *WorkloadHealth `json:"health,omitempty"`
	// Entrypoint defines the workload entrypoint.
	// +optional
	Entrypoint *WorkloadEntrypoint `json:"entrypoint,omitempty"`
	// APIAccess controls whether Claims derived from this workload receive
	// an in-cluster Boilerhouse API token and which scopes it carries.
	// +optional
	APIAccess *WorkloadAPIAccess `json:"apiAccess,omitempty"`
	// Security overrides the default pod/container security context (e.g. to run
	// as a specific uid/gid with an fsGroup so a non-root image can own its
	// mounted overlay volumes). Optional; unset keeps the hardened defaults.
	// +optional
	Security *WorkloadSecurity `json:"security,omitempty"`
}

// WorkloadSecurity overrides the default pod security context. The defaults are
// already hardened (all capabilities dropped, no privilege escalation,
// RuntimeDefault seccomp); these additionally pin the user/group the workload
// runs as and the fsGroup that owns its mounted (emptyDir) overlay volumes —
// required when a non-root image must write a mounted workspace.
type WorkloadSecurity struct {
	// RunAsUser sets the pod-level runAsUser (uid).
	// +optional
	RunAsUser *int64 `json:"runAsUser,omitempty"`
	// RunAsGroup sets the pod-level runAsGroup (gid).
	// +optional
	RunAsGroup *int64 `json:"runAsGroup,omitempty"`
	// FsGroup sets the pod fsGroup — the supplemental gid that owns mounted
	// volumes, so a non-root runAsUser can write them.
	// +optional
	FsGroup *int64 `json:"fsGroup,omitempty"`
	// RunAsNonRoot requires the container to run as a non-root user (admission
	// rejects a root image when true).
	// +optional
	RunAsNonRoot *bool `json:"runAsNonRoot,omitempty"`
}

// WorkloadAPIAccess configures agent-facing access to the Boilerhouse API.
type WorkloadAPIAccess struct {
	// Scopes overrides the default agent scope set granted to Claims of this
	// workload. A single entry of "none" disables API access entirely — no
	// token secret is provisioned and no env vars are injected.
	// +optional
	Scopes []string `json:"scopes,omitempty"`
}

// BoilerhouseWorkloadStatus defines the observed state of a BoilerhouseWorkload.
type BoilerhouseWorkloadStatus struct {
	// Phase is the current phase of the workload.
	// +optional
	// +kubebuilder:validation:Enum=Creating;Ready;Error
	Phase string `json:"phase,omitempty"`
	// Detail provides additional information about the current phase.
	// +optional
	Detail string `json:"detail,omitempty"`
	// ObservedGeneration is the most recent generation observed.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=bhw
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image.ref`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// BoilerhouseWorkload is the Schema for the boilerhouseworkloads API.
type BoilerhouseWorkload struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BoilerhouseWorkloadSpec   `json:"spec,omitempty"`
	Status BoilerhouseWorkloadStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BoilerhouseWorkloadList contains a list of BoilerhouseWorkload.
type BoilerhouseWorkloadList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BoilerhouseWorkload `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BoilerhouseWorkload{}, &BoilerhouseWorkloadList{})
}
