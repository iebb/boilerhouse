package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	v1alpha1 "github.com/zdavison/boilerhouse/go/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func credTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("clientgo scheme: %v", err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("v1alpha1 scheme: %v", err)
	}
	return s
}

func putCredentials(t *testing.T, srv *Server, workload string, body credentialsRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/workloads/"+workload+"/credentials", bytes.NewReader(raw))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", workload)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	srv.setWorkloadCredentials(rr, req)
	return rr
}

// The credential token is stored in a Secret and referenced via secretKeyRef —
// never persisted in the workload spec, and GET redacts any literal value.
func TestSetWorkloadCredentials_StoresSecretNotSpec(t *testing.T) {
	const ns = "boilerhouse"
	wl := &v1alpha1.BoilerhouseWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: "box-1", Namespace: ns, UID: "uid-1"},
		Spec: v1alpha1.BoilerhouseWorkloadSpec{
			Network: &v1alpha1.WorkloadNetwork{Access: "restricted", Allowlist: []string{"api.anthropic.com"}},
		},
	}
	fc := fake.NewClientBuilder().WithScheme(credTestScheme(t)).WithObjects(wl).Build()
	srv := &Server{client: fc, namespace: ns}

	rr := putCredentials(t, srv, "box-1", credentialsRequest{Credentials: []credentialDomain{{
		Domain:  "api.anthropic.com",
		Headers: []credentialHeader{{Name: "x-api-key", Value: "sk-ant-secret"}},
	}}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	// Secret carries the token, owned by the workload.
	var sec corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "wlcred-box-1", Namespace: ns}, &sec); err != nil {
		t.Fatalf("credential secret not created: %v", err)
	}
	key := credentialSecretKey("api.anthropic.com", "x-api-key")
	if got := string(sec.Data[key]); got != "sk-ant-secret" {
		t.Fatalf("secret value = %q, want sk-ant-secret", got)
	}
	if len(sec.OwnerReferences) != 1 || sec.OwnerReferences[0].Name != "box-1" {
		t.Fatalf("secret ownerRef = %+v, want workload box-1", sec.OwnerReferences)
	}

	// Workload spec references the Secret, never the literal token.
	var got v1alpha1.BoilerhouseWorkload
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "box-1", Namespace: ns}, &got); err != nil {
		t.Fatal(err)
	}
	h := got.Spec.Network.Credentials[0].Headers[0]
	if h.Value != "" {
		t.Fatalf("literal token leaked into spec: %q", h.Value)
	}
	if h.ValueFrom == nil || h.ValueFrom.SecretKeyRef == nil ||
		h.ValueFrom.SecretKeyRef.Name != "wlcred-box-1" || h.ValueFrom.SecretKeyRef.Key != key {
		t.Fatalf("secretKeyRef not wired: %+v", h.ValueFrom)
	}
	// access/allowlist left intact (caller's responsibility, not clobbered).
	if got.Spec.Network.Access != "restricted" {
		t.Fatalf("access changed to %q", got.Spec.Network.Access)
	}

	// GET redacts any inline literal value defensively.
	got.Spec.Network.Credentials[0].Headers[0] = v1alpha1.HeaderEntry{Name: "x-api-key", Value: "leak"}
	if v := toWorkloadResponse(&got).Spec.Network.Credentials[0].Headers[0].Value; v != "***" {
		t.Fatalf("GET did not redact literal value: %q", v)
	}
}

// An empty credentials list clears the Secret and the spec entries.
func TestSetWorkloadCredentials_ClearRemovesSecret(t *testing.T) {
	const ns = "boilerhouse"
	wl := &v1alpha1.BoilerhouseWorkload{
		ObjectMeta: metav1.ObjectMeta{Name: "box-2", Namespace: ns, UID: "uid-2"},
		Spec:       v1alpha1.BoilerhouseWorkloadSpec{Network: &v1alpha1.WorkloadNetwork{Access: "restricted"}},
	}
	fc := fake.NewClientBuilder().WithScheme(credTestScheme(t)).WithObjects(wl).Build()
	srv := &Server{client: fc, namespace: ns}

	if rr := putCredentials(t, srv, "box-2", credentialsRequest{Credentials: []credentialDomain{{
		Domain: "api.openai.com", Headers: []credentialHeader{{Name: "authorization", Value: "Bearer sk-x"}},
	}}}); rr.Code != http.StatusOK {
		t.Fatalf("set: status %d: %s", rr.Code, rr.Body.String())
	}
	if rr := putCredentials(t, srv, "box-2", credentialsRequest{}); rr.Code != http.StatusOK {
		t.Fatalf("clear: status %d: %s", rr.Code, rr.Body.String())
	}

	var sec corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "wlcred-box-2", Namespace: ns}, &sec); err == nil {
		t.Fatal("credential secret should have been deleted on clear")
	}
	var got v1alpha1.BoilerhouseWorkload
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "box-2", Namespace: ns}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Spec.Network.Credentials) != 0 {
		t.Fatalf("credentials not cleared from spec: %+v", got.Spec.Network.Credentials)
	}
}

func TestSetWorkloadCredentials_MissingWorkload404(t *testing.T) {
	fc := fake.NewClientBuilder().WithScheme(credTestScheme(t)).Build()
	srv := &Server{client: fc, namespace: "boilerhouse"}
	rr := putCredentials(t, srv, "nope", credentialsRequest{Credentials: []credentialDomain{{
		Domain: "api.anthropic.com", Headers: []credentialHeader{{Name: "x-api-key", Value: "v"}},
	}}})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}
