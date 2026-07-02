package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// instanceResponse is the JSON representation of a managed Pod.
type instanceResponse struct {
	Name         string            `json:"name"`
	Phase        string            `json:"phase"`
	TenantId     string            `json:"tenantId,omitempty"`
	WorkloadRef  string            `json:"workloadRef,omitempty"`
	IP           string            `json:"ip,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	CreatedAt    string            `json:"createdAt"`
	LastActivity string            `json:"lastActivity,omitempty"`
	ClaimedAt    string            `json:"claimedAt,omitempty"`
}

func toInstanceResponse(pod *corev1.Pod) instanceResponse {
	return instanceResponse{
		Name:        pod.Name,
		Phase:       string(pod.Status.Phase),
		TenantId:    pod.Labels["boilerhouse.dev/tenant"],
		WorkloadRef: pod.Labels["boilerhouse.dev/workload"],
		IP:          pod.Status.PodIP,
		Labels:      pod.Labels,
		CreatedAt:   pod.CreationTimestamp.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func (s *Server) listInstances(w http.ResponseWriter, r *http.Request) {
	var pods corev1.PodList
	if err := s.client.List(r.Context(), &pods,
		client.InNamespace(s.namespace),
		client.MatchingLabels{"boilerhouse.dev/managed": "true"},
	); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list instances: "+err.Error())
		return
	}

	// Fetch all claims to enrich instances with activity/claim timestamps.
	var claims v1alpha1.BoilerhouseClaimList
	claimByInstance := map[string]*v1alpha1.BoilerhouseClaim{}
	if err := s.client.List(r.Context(), &claims, client.InNamespace(s.namespace)); err == nil {
		for i := range claims.Items {
			if claims.Items[i].Status.InstanceId != "" {
				claimByInstance[claims.Items[i].Status.InstanceId] = &claims.Items[i]
			}
		}
	}

	items := make([]instanceResponse, 0, len(pods.Items))
	for i := range pods.Items {
		resp := toInstanceResponse(&pods.Items[i])
		if claim, ok := claimByInstance[resp.Name]; ok {
			if claim.Annotations != nil {
				resp.LastActivity = claim.Annotations["boilerhouse.dev/last-activity"]
			}
			if claim.Status.ClaimedAt != nil {
				resp.ClaimedAt = claim.Status.ClaimedAt.UTC().Format("2006-01-02T15:04:05Z")
			}
		}
		items = append(items, resp)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) getInstance(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var pod corev1.Pod
	key := types.NamespacedName{Name: id, Namespace: s.namespace}
	if err := s.client.Get(r.Context(), key, &pod); err != nil {
		writeError(w, http.StatusNotFound, "instance not found: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, toInstanceResponse(&pod))
}

func (s *Server) getInstanceLogs(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Verify the pod exists via the controller-runtime client.
	var pod corev1.Pod
	key := types.NamespacedName{Name: id, Namespace: s.namespace}
	if err := s.client.Get(r.Context(), key, &pod); err != nil {
		writeError(w, http.StatusNotFound, "instance not found: "+err.Error())
		return
	}

	// pods/log via the typed clientset — the controller-runtime client can't
	// read subresources, and kubectl isn't in the api image.
	if s.clientset == nil {
		writeError(w, http.StatusInternalServerError, "kubernetes rest config unavailable")
		return
	}
	opts := &corev1.PodLogOptions{}
	if tailLines := r.URL.Query().Get("tail"); tailLines != "" {
		if n, err := strconv.ParseInt(tailLines, 10, 64); err == nil && n > 0 {
			opts.TailLines = &n
		}
	}
	out, err := s.clientset.CoreV1().Pods(s.namespace).GetLogs(id, opts).DoRaw(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get logs: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

// execRequest is the JSON body for executing a command in an instance.
type execRequest struct {
	Command []string `json:"command"`
}

// execResponse is the JSON response from exec.
type execResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

func (s *Server) execInInstance(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if len(req.Command) == 0 {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}

	// Buffered SPDY exec via client-go remotecommand — the controller-runtime
	// client can't exec, and kubectl isn't in the api image.
	if s.clientset == nil || s.restConfig == nil {
		writeError(w, http.StatusInternalServerError, "kubernetes rest config unavailable")
		return
	}
	execReq := s.clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(id).Namespace(s.namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: req.Command,
			Stdout:  true,
			Stderr:  true,
		}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(s.restConfig, http.MethodPost, execReq.URL())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "exec failed: "+err.Error())
		return
	}

	var stdout, stderr bytes.Buffer
	exitCode := 0
	if err := executor.StreamWithContext(r.Context(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		var codeErr utilexec.CodeExitError
		if errors.As(err, &codeErr) {
			exitCode = codeErr.Code
		} else {
			writeError(w, http.StatusInternalServerError, "exec failed: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, execResponse{
		Stdout:   strings.TrimRight(stdout.String(), "\n"),
		Stderr:   strings.TrimRight(stderr.String(), "\n"),
		ExitCode: exitCode,
	})
}

func (s *Server) destroyInstance(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	pod := &corev1.Pod{}
	key := types.NamespacedName{Name: id, Namespace: s.namespace}
	if err := s.client.Get(r.Context(), key, pod); err != nil {
		writeError(w, http.StatusNotFound, "instance not found: "+err.Error())
		return
	}

	if err := s.client.Delete(r.Context(), pod); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to destroy instance: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "destroyed", "instance": id})
}

