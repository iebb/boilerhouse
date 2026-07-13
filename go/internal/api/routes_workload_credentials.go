package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
)

// credentialsRequest is the JSON body for PUT /workloads/{name}/credentials.
//
// Each header carries a plaintext token supplied over the (TLS) API. The server
// stores every value in a Secret in the operator namespace and rewrites the
// workload's network.credentials to reference it via secretKeyRef — so the token
// is NEVER persisted in the Workload CR spec, and never returned by GET. This is
// the generic per-workload credential-injection capability: a caller sets a
// per-domain header (e.g. x-api-key on api.anthropic.com) and Envoy injects it on
// egress, keeping the secret out of the workload entirely. Injection additionally
// requires network.access: restricted (Envoy in the path) — the caller's job to set.
type credentialsRequest struct {
	Credentials []credentialDomain `json:"credentials"`
}

type credentialDomain struct {
	Domain  string             `json:"domain"`
	Headers []credentialHeader `json:"headers"`
}

type credentialHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// setWorkloadCredentials stores per-domain credential headers for a workload as a
// Secret (owned by the workload for GC) and points network.credentials at it via
// secretKeyRef. An empty credentials list clears them (deletes the Secret). PUT is
// idempotent — re-sending replaces the stored values (e.g. on token refresh).
func (s *Server) setWorkloadCredentials(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req credentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// The workload must exist so the Secret can be owned by it (GC on delete).
	var wl v1alpha1.BoilerhouseWorkload
	key := types.NamespacedName{Name: name, Namespace: s.namespace}
	if err := s.client.Get(r.Context(), key, &wl); err != nil {
		writeError(w, http.StatusNotFound, "workload not found: "+err.Error())
		return
	}

	secretName := credentialSecretName(name)
	secretData := map[string][]byte{}
	var creds []v1alpha1.NetworkCredential
	for _, d := range req.Credentials {
		if d.Domain == "" {
			writeError(w, http.StatusBadRequest, "credential entry missing domain")
			return
		}
		var headers []v1alpha1.HeaderEntry
		for _, h := range d.Headers {
			if h.Name == "" || h.Value == "" {
				writeError(w, http.StatusBadRequest, "credential header requires name and value")
				return
			}
			k := credentialSecretKey(d.Domain, h.Name)
			secretData[k] = []byte(h.Value)
			headers = append(headers, v1alpha1.HeaderEntry{
				Name: h.Name,
				ValueFrom: &v1alpha1.HeaderValueSource{
					SecretKeyRef: &v1alpha1.SecretKeyRef{Name: secretName, Key: k},
				},
			})
		}
		creds = append(creds, v1alpha1.NetworkCredential{Domain: d.Domain, Headers: headers})
	}

	if len(secretData) == 0 {
		if err := s.deleteCredentialSecret(r.Context(), secretName); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to clear credential secret: "+err.Error())
			return
		}
	} else if err := s.upsertCredentialSecret(r.Context(), &wl, secretName, secretData); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store credential secret: "+err.Error())
		return
	}

	// Re-fetch + update under RetryOnConflict: this PUT typically lands moments
	// after the workload is created, while the operator is still reconciling it
	// (finalizers/status), so a plain Update races the controller's writes and
	// 409s ("object has been modified"). Retrying with a fresh Get converges.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cur v1alpha1.BoilerhouseWorkload
		if e := s.client.Get(r.Context(), key, &cur); e != nil {
			return e
		}
		if cur.Spec.Network == nil {
			cur.Spec.Network = &v1alpha1.WorkloadNetwork{}
		}
		cur.Spec.Network.Credentials = creds
		return s.client.Update(r.Context(), &cur)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update workload: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "domains": len(creds)})
}

// credentialSecretName is the deterministic Secret name for a workload's
// injected credentials.
func credentialSecretName(workload string) string {
	return "wlcred-" + workload
}

// credentialSecretKey is a deterministic, Secret-key-safe id for a (domain,
// header) pair. Secret data keys must match [-._a-zA-Z0-9]+.
func credentialSecretKey(domain, header string) string {
	return sanitizeSecretKey(domain + "_" + header)
}

func sanitizeSecretKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func (s *Server) upsertCredentialSecret(ctx context.Context, wl *v1alpha1.BoilerhouseWorkload, name string, data map[string][]byte) error {
	block := true
	owner := metav1.OwnerReference{
		APIVersion:         v1alpha1.GroupVersion.String(),
		Kind:               "BoilerhouseWorkload",
		Name:               wl.Name,
		UID:                wl.UID,
		BlockOwnerDeletion: &block,
	}
	var existing corev1.Secret
	err := s.client.Get(ctx, types.NamespacedName{Name: name, Namespace: s.namespace}, &existing)
	if apierrors.IsNotFound(err) {
		return s.client.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       s.namespace,
				OwnerReferences: []metav1.OwnerReference{owner},
				Labels:          map[string]string{"boilerhouse.dev/credential-workload": wl.Name},
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		})
	}
	if err != nil {
		return err
	}
	existing.Data = data
	existing.OwnerReferences = []metav1.OwnerReference{owner}
	return s.client.Update(ctx, &existing)
}

func (s *Server) deleteCredentialSecret(ctx context.Context, name string) error {
	err := s.client.Delete(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.namespace},
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
