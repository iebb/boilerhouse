package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	snapshotsPVCName      = "boilerhouse-snapshots"
	snapshotHelperPodName = "boilerhouse-snapshot-helper"
	snapshotHelperImage   = "busybox:1.36"
	snapshotsPVCSize      = "50Gi"
	snapshotsMountPath    = "/snapshots"
	snapshotHelperUID     = int64(65534) // nobody
)

// hashArchive returns the lowercase hex sha256 of the given bytes.
func hashArchive(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// verifyArchive returns nil if sha (lowercase hex, possibly whitespace-padded)
// matches sha256(archive). Used by InjectSnapshot to detect partial writes or
// PVC-level corruption before streaming into a tenant pod.
func verifyArchive(archive []byte, sha string) error {
	want := strings.TrimSpace(sha)
	if want == "" {
		return fmt.Errorf("missing checksum")
	}
	got := hashArchive(archive)
	if got != want {
		return fmt.Errorf("checksum mismatch: want %s, got %s", want, got)
	}
	return nil
}

// Snapshotter abstracts overlay snapshot storage so the claim reconciler can
// be unit-tested without a real kubectl-backed SnapshotManager.
type Snapshotter interface {
	HasSnapshot(ctx context.Context, tenantId, workloadName string) (bool, error)
	InjectSnapshot(ctx context.Context, podName, tenantId, workloadName string) error
	ExtractAndStore(ctx context.Context, podName, tenantId, workloadName string, overlayDirs []string) error
	DeleteSnapshot(ctx context.Context, tenantId, workloadName string) error
}

// SnapshotManager handles storing and retrieving tenant overlay snapshots.
// It uses kubectl exec to interact with Pods and a long-running helper Pod
// that mounts the shared snapshots PVC for file I/O.
type SnapshotManager struct {
	namespace  string
	k8s        client.Client
	restConfig *rest.Config
}

// NewSnapshotManager creates a new SnapshotManager for the given namespace.
// restConfig is the in-cluster config used to exec into pods via client-go
// remotecommand — the operator image ships no kubectl binary.
func NewSnapshotManager(namespace string, k8s client.Client, restConfig *rest.Config) *SnapshotManager {
	return &SnapshotManager{
		namespace:  namespace,
		k8s:        k8s,
		restConfig: restConfig,
	}
}

// podExec runs a command inside a pod over the in-cluster API using client-go's
// SPDY remotecommand executor — the in-process equivalent of `kubectl exec`,
// needing no external binary or kubeconfig. stdin/stdout/stderr are attached
// only when non-nil; a non-zero command exit returns an error.
func (s *SnapshotManager) podExec(ctx context.Context, podName string, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cs, err := kubernetes.NewForConfig(s.restConfig)
	if err != nil {
		return fmt.Errorf("build clientset: %w", err)
	}
	req := cs.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace(s.namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: command,
			Stdin:   stdin != nil,
			Stdout:  stdout != nil,
			Stderr:  stderr != nil,
		}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("init pod-exec executor: %w", err)
	}
	return executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: stdin, Stdout: stdout, Stderr: stderr})
}

// snapshotPath returns the path within the snapshots PVC for a tenant's workload.
func snapshotPath(tenantId, workloadName string) string {
	return fmt.Sprintf("/snapshots/%s/%s.tar.gz", tenantId, workloadName)
}

// snapshotSHAPath returns the path of the sidecar checksum for a snapshot.
func snapshotSHAPath(tenantId, workloadName string) string {
	return snapshotPath(tenantId, workloadName) + ".sha256"
}

// ExtractAndStore extracts overlay directories from a running Pod and stores
// the resulting tar.gz archive in the snapshots PVC.
func (s *SnapshotManager) ExtractAndStore(ctx context.Context, podName, tenantId, workloadName string, overlayDirs []string) error {
	if len(overlayDirs) == 0 {
		return nil
	}

	// 1. Extract overlay from the tenant Pod as a tar.gz archive on stdout.
	tarArgs := append([]string{"tar", "czf", "-", "-C", "/"}, stripLeadingSlashes(overlayDirs)...)
	var archive bytes.Buffer
	var stderr bytes.Buffer
	if err := s.podExec(ctx, podName, tarArgs, nil, &archive, &stderr); err != nil {
		return fmt.Errorf("extract overlay from pod %s: %w (stderr: %s)", podName, err, stderr.String())
	}

	if archive.Len() == 0 {
		return nil // nothing to store
	}

	// 2. Write the archive + sha256 sidecar atomically to the snapshots PVC.
	return s.writeToSnapshotsPVC(ctx, tenantId, workloadName, archive.Bytes())
}

// readSnapshotChecksum returns the stored sha256 hex for a tenant's snapshot,
// or an error if the sidecar is missing.
func (s *SnapshotManager) readSnapshotChecksum(ctx context.Context, tenantId, workloadName string) (string, error) {
	raw, err := s.readFromSnapshotsPVC(ctx, snapshotSHAPath(tenantId, workloadName))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// HasSnapshot checks whether a snapshot archive exists for the given tenant+workload.
func (s *SnapshotManager) HasSnapshot(ctx context.Context, tenantId, workloadName string) (bool, error) {
	if err := s.ensureHelperPod(ctx); err != nil {
		return false, fmt.Errorf("ensuring helper pod: %w", err)
	}
	path := snapshotPath(tenantId, workloadName)
	return s.fileExistsInPVC(ctx, path)
}

// InjectSnapshot reads a snapshot from the PVC and injects it into a running Pod
// via kubectl exec tar extract. The sha256 sidecar is verified before any bytes
// stream into the tenant pod — a mismatch or missing sidecar fails the inject
// so the claim reconciler can retry.
func (s *SnapshotManager) InjectSnapshot(ctx context.Context, podName, tenantId, workloadName string) error {
	path := snapshotPath(tenantId, workloadName)

	// 1. Read the archive from the snapshots PVC.
	archive, err := s.readFromSnapshotsPVC(ctx, path)
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}
	if len(archive) == 0 {
		return nil
	}

	// 1b. Verify integrity against the sidecar checksum.
	sha, err := s.readSnapshotChecksum(ctx, tenantId, workloadName)
	if err != nil {
		return fmt.Errorf("read snapshot checksum: %w", err)
	}
	if err := verifyArchive(archive, sha); err != nil {
		return fmt.Errorf("snapshot %s: %w", path, err)
	}

	// 2. Inject into the target Pod.
	// --no-same-owner + --no-same-permissions: skip restoring uid/gid/mode on
	// pre-existing directories (e.g. /workspace, /home/claude) that were created
	// by the container image with different perms. Without these flags, tar
	// fails with "Cannot utime / Cannot change mode: Operation not permitted".
	var stderr bytes.Buffer
	if err := s.podExec(ctx, podName,
		[]string{"tar", "xzf", "-", "-C", "/", "--no-same-owner", "--no-same-permissions"},
		bytes.NewReader(archive), nil, &stderr); err != nil {
		return fmt.Errorf("inject snapshot into pod %s: %w (stderr: %s)", podName, err, stderr.String())
	}

	return nil
}

// DeleteSnapshot removes a stored snapshot (archive + sidecar checksum) for a
// tenant+workload.
func (s *SnapshotManager) DeleteSnapshot(ctx context.Context, tenantId, workloadName string) error {
	if err := s.ensureHelperPod(ctx); err != nil {
		return fmt.Errorf("ensuring helper pod: %w", err)
	}
	path := snapshotPath(tenantId, workloadName)
	shaPath := snapshotSHAPath(tenantId, workloadName)

	var stderr bytes.Buffer
	// Ignore errors (file may not exist).
	_ = s.podExec(ctx, snapshotHelperPodName, []string{"rm", "-f", path, shaPath}, nil, nil, &stderr)
	return nil
}

// ensureSnapshotsPVC creates the shared snapshots PVC if it does not exist.
func (s *SnapshotManager) ensureSnapshotsPVC(ctx context.Context) error {
	var pvc corev1.PersistentVolumeClaim
	key := types.NamespacedName{Name: snapshotsPVCName, Namespace: s.namespace}
	if err := s.k8s.Get(ctx, key, &pvc); err == nil {
		return nil // already exists
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("checking snapshots PVC: %w", err)
	}

	pvc = corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      snapshotsPVCName,
			Namespace: s.namespace,
			Labels: map[string]string{
				LabelManaged: "true",
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(snapshotsPVCSize),
				},
			},
		},
	}

	if err := s.k8s.Create(ctx, &pvc); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating snapshots PVC: %w", err)
	}
	return nil
}

// ensureHelperPod creates the long-running snapshot helper Pod if it does not exist.
// The helper Pod mounts the shared snapshots PVC and is used for all PVC file operations.
func (s *SnapshotManager) ensureHelperPod(ctx context.Context) error {
	// Ensure the PVC exists first.
	if err := s.ensureSnapshotsPVC(ctx); err != nil {
		return err
	}

	var pod corev1.Pod
	key := types.NamespacedName{Name: snapshotHelperPodName, Namespace: s.namespace}
	if err := s.k8s.Get(ctx, key, &pod); err == nil {
		// Pod exists. Check if it's running.
		if pod.Status.Phase == corev1.PodRunning {
			return nil
		}
		// If not running and not pending, delete and recreate.
		if pod.Status.Phase != corev1.PodPending {
			if err := s.k8s.Delete(ctx, &pod); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("deleting failed helper pod: %w", err)
			}
			// Fall through to create.
		} else {
			return nil // still starting up
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("checking helper pod: %w", err)
	}

	falseVal := false
	trueVal := true
	terminationGrace := int64(1)
	uid := int64(snapshotHelperUID)
	pod = corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      snapshotHelperPodName,
			Namespace: s.namespace,
			Labels: map[string]string{
				LabelManaged: "true",
				"app":        "boilerhouse-snapshot-helper",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "helper",
					Image:   snapshotHelperImage,
					Command: []string{"sleep", "infinity"},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "snapshots",
							MountPath: snapshotsMountPath,
						},
					},
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: &falseVal,
						ReadOnlyRootFilesystem:   &trueVal,
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "snapshots",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: snapshotsPVCName,
						},
					},
				},
			},
			RestartPolicy:                 corev1.RestartPolicyAlways,
			AutomountServiceAccountToken:  &falseVal,
			TerminationGracePeriodSeconds: &terminationGrace,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &trueVal,
				RunAsUser:    &uid,
				RunAsGroup:   &uid,
				FSGroup:      &uid, // make /snapshots writable by UID 65534
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
		},
	}

	if err := s.k8s.Create(ctx, &pod); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating helper pod: %w", err)
	}
	return nil
}

// writeToSnapshotsPVC atomically writes the archive + sha256 sidecar for a
// tenant/workload snapshot. The archive is first streamed to "<path>.tmp" and
// the checksum to "<path>.sha256.tmp", then both are renamed into place in a
// single shell invocation. A partial stream therefore never replaces a
// previously-good snapshot.
func (s *SnapshotManager) writeToSnapshotsPVC(ctx context.Context, tenantId, workloadName string, data []byte) error {
	if err := s.ensureHelperPod(ctx); err != nil {
		return fmt.Errorf("ensuring helper pod: %w", err)
	}

	path := snapshotPath(tenantId, workloadName)
	shaPath := snapshotSHAPath(tenantId, workloadName)
	dir := fmt.Sprintf("/snapshots/%s", tenantId)
	sum := hashArchive(data)

	// tenantId/workloadName are controller-originated (not user input) so
	// shell-interpolating them into the one-liner below is safe. The
	// checksum is hex, also safe. If any of these gain user-controlled
	// sources in the future, switch this to a stdin-fed shell script.
	script := fmt.Sprintf(
		"set -e; mkdir -p %s; cat > %s.tmp; printf '%%s' %s > %s.tmp; mv %s.tmp %s; mv %s.tmp %s",
		dir,
		path,
		sum, shaPath,
		path, path,
		shaPath, shaPath,
	)

	var stderr bytes.Buffer
	if err := s.podExec(ctx, snapshotHelperPodName, []string{"sh", "-c", script},
		bytes.NewReader(data), nil, &stderr); err != nil {
		return fmt.Errorf("writing snapshot %s: %w (stderr: %s)", path, err, stderr.String())
	}

	return nil
}

// readFromSnapshotsPVC reads a file from the snapshots PVC via the helper Pod.
func (s *SnapshotManager) readFromSnapshotsPVC(ctx context.Context, path string) ([]byte, error) {
	if err := s.ensureHelperPod(ctx); err != nil {
		return nil, fmt.Errorf("ensuring helper pod: %w", err)
	}

	var out bytes.Buffer
	var stderr bytes.Buffer
	if err := s.podExec(ctx, snapshotHelperPodName, []string{"cat", path}, nil, &out, &stderr); err != nil {
		return nil, fmt.Errorf("reading %s: %w (stderr: %s)", path, err, stderr.String())
	}
	return out.Bytes(), nil
}

// fileExistsInPVC checks if a file exists in the snapshots PVC via the helper Pod.
func (s *SnapshotManager) fileExistsInPVC(ctx context.Context, path string) (bool, error) {
	// Resolve existence via stdout ("yes"/"no") rather than the command's exit
	// code — remotecommand surfaces a non-zero exit as a typed error, but echoing
	// keeps this a plain success path. path is controller-originated (safe to
	// interpolate). Single-quote to be safe against spaces.
	var out bytes.Buffer
	if err := s.podExec(ctx, snapshotHelperPodName,
		[]string{"sh", "-c", fmt.Sprintf("test -f '%s' && echo yes || echo no", path)},
		nil, &out, nil); err != nil {
		return false, err
	}
	return strings.TrimSpace(out.String()) == "yes", nil
}

// stripLeadingSlashes removes leading "/" from directory paths for use as tar arguments.
func stripLeadingSlashes(dirs []string) []string {
	result := make([]string, len(dirs))
	for i, d := range dirs {
		result[i] = strings.TrimPrefix(d, "/")
	}
	return result
}
