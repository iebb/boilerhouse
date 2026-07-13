package envoy

import (
	"bytes"
	"strings"
	"text/template"
)

// ResolvedCredential holds a domain and its resolved HTTP headers.
type ResolvedCredential struct {
	Domain  string
	Headers map[string]string
}

// EnvoyConfig holds the inputs needed to generate an Envoy bootstrap YAML.
//
// Three tiers of egress through the sidecar:
//   - Credentials: per-domain MITM — TLS is terminated with a minted cert (or
//     plain HTTP accepted), the configured headers are injected, and the
//     request is forwarded upstream over TLS.
//   - Allowlist: SNI/Host PASSTHROUGH — bytes are proxied untouched to the
//     original destination (no TLS termination, no CA trust needed, no header
//     injection). This is what keeps a credentialed workload's other
//     dependencies (package registries, git hosts, its own control plane)
//     reachable.
//   - Everything else: denied (HTTP 403 / connection refused at the TLS
//     listener) — unless PassthroughAll.
type EnvoyConfig struct {
	Allowlist   []string
	Credentials []ResolvedCredential
	TLS         *TLSMaterial // nil if no TLS interception needed
	// PassthroughAll adds a default passthrough (access: unrestricted): any
	// destination not credentialed or allowlisted is proxied untouched instead
	// of denied. Credential injection stays orthogonal to the access level.
	PassthroughAll bool
}

// SafeDomain replaces characters that are invalid in Envoy cluster/route names.
func SafeDomain(domain string) string {
	r := strings.NewReplacer(".", "_", "*", "_")
	return r.Replace(domain)
}

// envoyView is the pre-processed template input: Passthrough is the Allowlist
// minus credential domains (a credentialed domain must terminate at its MITM
// chain — a duplicate SNI match would be invalid config), deduped in order.
type envoyView struct {
	Credentials    []ResolvedCredential
	Passthrough    []string
	PassthroughAll bool
	TLS            *TLSMaterial
	HasPassthrough bool
}

// GenerateEnvoyYAML renders the Envoy bootstrap configuration YAML.
func GenerateEnvoyYAML(cfg EnvoyConfig) (string, error) {
	funcMap := template.FuncMap{
		"safeDomain": SafeDomain,
	}

	tmpl, err := template.New("envoy").Funcs(funcMap).Parse(envoyTemplate)
	if err != nil {
		return "", err
	}

	credDomains := map[string]bool{}
	for _, c := range cfg.Credentials {
		credDomains[c.Domain] = true
	}
	seen := map[string]bool{}
	var passthrough []string
	for _, d := range cfg.Allowlist {
		if d == "" || credDomains[d] || seen[d] {
			continue
		}
		seen[d] = true
		passthrough = append(passthrough, d)
	}
	view := envoyView{
		Credentials:    cfg.Credentials,
		Passthrough:    passthrough,
		PassthroughAll: cfg.PassthroughAll,
		TLS:            cfg.TLS,
		HasPassthrough: len(passthrough) > 0 || cfg.PassthroughAll,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, view); err != nil {
		return "", err
	}
	return buf.String(), nil
}

const envoyTemplate = `admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 18081

static_resources:
  listeners:
    - name: egress_http
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 18080
{{- if .HasPassthrough}}
      listener_filters:
        - name: envoy.filters.listener.original_dst
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
{{- end}}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: egress_http
                upgrade_configs:
                  - upgrade_type: websocket
                route_config:
                  virtual_hosts:
{{- range .Credentials}}
                    - name: {{safeDomain .Domain}}
                      domains:
                        - "{{.Domain}}"
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: upstream_{{safeDomain .Domain}}
                            # LLM streaming responses can take minutes.
                            timeout: 600s
                          request_headers_to_add:
{{- range $key, $val := .Headers}}
                            - header:
                                key: "{{$key}}"
                                value: "{{$val}}"
                              append_action: OVERWRITE_IF_EXISTS_OR_ADD
{{- end}}
{{- end}}
{{- range .Passthrough}}
                    - name: pt_{{safeDomain .}}
                      domains:
                        - "{{.}}"
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: passthrough_original_dst
                            timeout: 600s
{{- end}}
{{- if .PassthroughAll}}
                    - name: passthrough_all
                      domains:
                        - "*"
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: passthrough_original_dst
                            timeout: 600s
{{- else}}
                    - name: deny_all
                      domains:
                        - "*"
                      routes:
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 403
                            body:
                              inline_string: "blocked by boilerhouse proxy"
{{- end}}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
{{- if .TLS}}
    - name: egress_tls
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 18443
      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
{{- if .HasPassthrough}}
        - name: envoy.filters.listener.original_dst
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
{{- end}}
      filter_chains:
{{- range .Credentials}}
        - filter_chain_match:
            server_names:
              - "{{.Domain}}"
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates:
                  - certificate_chain:
                      filename: /etc/envoy/{{safeDomain .Domain}}.crt
                    private_key:
                      filename: /etc/envoy/{{safeDomain .Domain}}.key
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: egress_tls_{{safeDomain .Domain}}
                route_config:
                  virtual_hosts:
                    - name: {{safeDomain .Domain}}_tls
                      domains:
                        - "{{.Domain}}"
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: upstream_{{safeDomain .Domain}}
                            # LLM streaming responses can take minutes.
                            timeout: 600s
                          request_headers_to_add:
{{- range $key, $val := .Headers}}
                            - header:
                                key: "{{$key}}"
                                value: "{{$val}}"
                              append_action: OVERWRITE_IF_EXISTS_OR_ADD
{{- end}}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
{{- end}}
{{- range .Passthrough}}
        - filter_chain_match:
            server_names:
              - "{{.}}"
          filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: pt_{{safeDomain .}}
                cluster: passthrough_original_dst
{{- end}}
{{- if .PassthroughAll}}
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: pt_default
                cluster: passthrough_original_dst
{{- end}}
{{- end}}

  clusters:
{{- range .Credentials}}
    - name: upstream_{{safeDomain .Domain}}
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      load_assignment:
        cluster_name: upstream_{{safeDomain .Domain}}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: {{.Domain}}
                      port_value: 443
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: {{.Domain}}
{{- end}}
{{- if .HasPassthrough}}
    - name: passthrough_original_dst
      type: ORIGINAL_DST
      lb_policy: CLUSTER_PROVIDED
      connect_timeout: 10s
{{- end}}
`
