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
type EnvoyConfig struct {
	Allowlist   []string
	Credentials []ResolvedCredential
	TLS         *TLSMaterial // nil if no TLS interception needed
}

// SafeDomain replaces characters that are invalid in Envoy cluster/route names.
func SafeDomain(domain string) string {
	r := strings.NewReplacer(".", "_", "*", "_")
	return r.Replace(domain)
}

// PassthroughDomains are allowlisted destinations that have NO injected
// credentials: Envoy SNI-routes them straight to the real host (TCP passthrough,
// no TLS termination/MITM), so the box does normal end-to-end TLS and no extra CA
// trust is needed. Domains that DO have credentials are served by the MITM
// chains instead, so they're excluded here to avoid duplicate routes/chains.
func (c EnvoyConfig) PassthroughDomains() []string {
	cred := make(map[string]bool, len(c.Credentials))
	for _, rc := range c.Credentials {
		cred[rc.Domain] = true
	}
	var out []string
	for _, d := range c.Allowlist {
		if d != "" && !cred[d] {
			out = append(out, d)
		}
	}
	return out
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

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
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
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: egress_http
                # Plain-HTTP WebSocket (e.g. an in-cluster control plane's ws://
                # reverse channel) must survive the proxy hop; without this the
                # HCM rejects Upgrade requests.
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
{{- range .PassthroughDomains}}
                    - name: allow_{{safeDomain .}}
                      domains:
                        - "{{.}}"
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: passthrough_http_{{safeDomain .}}
                            timeout: 600s
{{- end}}
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
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
{{- if or .TLS .Allowlist}}
    - name: egress_tls
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 18443
      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
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
{{- range .PassthroughDomains}}
        - filter_chain_match:
            server_names:
              - "{{.}}"
          filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: passthrough_tls_{{safeDomain .}}
                cluster: passthrough_tls_{{safeDomain .}}
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
{{- range .PassthroughDomains}}
    - name: passthrough_tls_{{safeDomain .}}
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      load_assignment:
        cluster_name: passthrough_tls_{{safeDomain .}}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: {{.}}
                      port_value: 443
    - name: passthrough_http_{{safeDomain .}}
      type: STRICT_DNS
      dns_lookup_family: V4_ONLY
      load_assignment:
        cluster_name: passthrough_http_{{safeDomain .}}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: {{.}}
                      port_value: 80
{{- end}}
`
