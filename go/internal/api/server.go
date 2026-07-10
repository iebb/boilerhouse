package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/zdavison/boilerhouse/go/internal/scope"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Server is the Boilerhouse REST API server. It translates HTTP requests
// into Kubernetes resource operations using the controller-runtime client.
type Server struct {
	client      client.Client
	restConfig  *rest.Config
	namespace   string
	apiKey      string
	tokens      *TokenStore
	corsOrigins []string
	router      chi.Router
}

// NewServer creates a new API server backed by the given Kubernetes client.
// The namespace determines where CRDs and Pods are managed.
// If BOILERHOUSE_API_KEY is set, Bearer-token auth is required on all
// routes except /health and /ws. When tokens is non-nil, scoped per-Claim
// tokens are also accepted — callers get an AuthContext that routes can
// query with RequireScope / RequireOwnTenant.
// The restConfig is optional; when provided it enables the /ws WebSocket
// endpoint for live dashboard event streaming.
func NewServer(k8sClient client.Client, restConfig *rest.Config, namespace string, tokens *TokenStore) *Server {
	var corsOrigins []string
	if v := os.Getenv("CORS_ORIGIN"); v != "" {
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				corsOrigins = append(corsOrigins, o)
			}
		}
	}

	s := &Server{
		client:      k8sClient,
		restConfig:  restConfig,
		namespace:   namespace,
		apiKey:      os.Getenv("BOILERHOUSE_API_KEY"),
		tokens:      tokens,
		corsOrigins: corsOrigins,
	}
	s.router = s.buildRouter()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(s.securityHeaders)
	r.Use(s.cors)

	// WebSocket endpoint — outside auth middleware so the dashboard can
	// connect without an API key (the TS proxy doesn't forward it).
	r.Get("/ws", s.handleWebSocket)

	r.Route("/api/v1", func(r chi.Router) {
		// Health is always accessible (no auth required).
		r.Get("/health", s.getHealth)
		r.Get("/stats", s.getStats)

		// Auth middleware for everything else.
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)

			// Admin-only routes (dashboard + operators). Scoped pod tokens
			// have no access here.
			r.Group(func(r chi.Router) {
				r.Use(requireAdmin)

				// Workloads
				r.Post("/workloads", s.createWorkload)
				r.Get("/workloads", s.listWorkloads)
				r.Get("/workloads/{name}", s.getWorkload)
				r.Put("/workloads/{name}", s.updateWorkload)
				r.Delete("/workloads/{name}", s.deleteWorkload)
				r.Put("/workloads/{name}/credentials", s.setWorkloadCredentials)
				r.Get("/workloads/{name}/snapshots", s.listWorkloadSnapshots)

				// Snapshots
				r.Get("/snapshots", s.listSnapshots)

				// Tenants (includes claim/release — agents do not claim
				// themselves; the dashboard/orchestrator does).
				r.Post("/tenants/{id}/claim", s.claimInstance)
				r.Post("/tenants/{id}/release", s.releaseInstance)
				r.Get("/tenants/{id}", s.getTenant)
				r.Get("/tenants", s.listTenants)

				// Instances
				r.Get("/instances", s.listInstances)
				r.Get("/instances/{id}", s.getInstance)
				r.Get("/instances/{id}/logs", s.getInstanceLogs)
				r.Post("/instances/{id}/exec", s.execInInstance)
				r.Post("/instances/{id}/destroy", s.destroyInstance)

				// Debug
				r.Get("/debug/resources", s.listDebugResources)
			})

			// Triggers — the only surface scoped pod tokens can reach.
			// Cross-tenant isolation is enforced inside each handler
			// (type==cron, own-tenant, own-workload).
			r.With(requireScope(scope.AgentTriggersRead)).Get("/triggers", s.listTriggers)
			r.With(requireScope(scope.AgentTriggersRead)).Get("/triggers/{id}", s.getTrigger)
			r.With(requireScope(scope.AgentTriggersWrite)).Post("/triggers", s.createTrigger)
			r.With(requireScope(scope.AgentTriggersWrite)).Delete("/triggers/{id}", s.deleteTrigger)
		})
	})

	return r
}

// securityHeaders adds standard security headers to every response.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// cors applies CORS headers when the request Origin is in the allowlist.
// No-op when CORS_ORIGIN is not set. Responds to OPTIONS preflight requests
// with 204 + the CORS headers.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.corsOrigins) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		allowed := false
		for _, o := range s.corsOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware enforces Bearer-token authentication. When no admin key
// is configured (BOILERHOUSE_API_KEY unset), auth is disabled — this is the
// dev-mode default. With an admin key set, the bearer token is matched
// first against it (constant-time), then against the scoped token store.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dev mode: no admin key configured → auth disabled. The token
		// store may still be running for scoped tokens, but without an
		// admin key the API is intended for local development.
		if s.apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == auth {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}

		// Admin path: constant-time compare against the global key.
		if s.apiKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.apiKey)) == 1 {
			ctx := ContextWithAuth(r.Context(), AuthContext{Kind: AuthAdmin})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Scoped path: look up the token in the per-Claim store.
		if s.tokens != nil {
			if ac, ok := s.tokens.Lookup(token); ok {
				next.ServeHTTP(w, r.WithContext(ContextWithAuth(r.Context(), ac)))
				return
			}
		}

		writeError(w, http.StatusUnauthorized, "invalid API key")
	})
}

// writeJSON writes v as JSON with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
