# Envoy-family gateways — agentgateway (solo.io), Istio, Envoy

These gateways have no in-process plugin system the way Kong does. Their authorization
extension point is the **Envoy External Authorization (`ext_authz`) filter**, so the "plugin"
here is a gRPC service: `coaz-pep` from [`../../core`](../../core), listening on `:9191` and
implementing `envoy.service.auth.v3.Authorization/Check`.

One binary serves all three. What differs is only how you attach it.

```
client ──▶ gateway ──ext_authz gRPC──▶ coaz-pep ──AuthZEN──▶ PDP (Ping Authorize)
              │                            │
              ▼ PERMIT                     ▼ DENY
        upstream service            401/403 + WWW-Authenticate, or a
                                    JSON-RPC error for MCP — passed through verbatim
```

It is a 1:1 port of the Kong `authzen-pdp` plugin, so both gateways send the PDP identical
evaluation requests:

| Kong plugin | Envoy-family equivalent |
| --- | --- |
| per-route plugin `config` | ext_authz `context_extensions` |
| claim extraction (`sub`, `act.sub`, `scope`, `cnf.jkt`, `acr`) | same logic in Go |
| DPoP sender-constraint (RFC 9449) | same |
| RFC 9470 step-up challenges | Envoy `DeniedHttpResponse` — status, `WWW-Authenticate` and body pass through unchanged |
| request → AuthZEN mapping | same patterns |
| `X-Auth-*` upstream headers | `OkHttpResponse.headers` |

**Always set `failureMode: deny`.** A PEP that fails open is not a PEP.

## agentgateway (solo.io)

[`agentgateway/`](agentgateway) holds a worked config — `config.yaml.template`, a
Dockerfile and an entrypoint that substitutes `__PLACEHOLDER__` tokens at container start
so one image works in compose and on Railway.

It is a real deployment's config, not a generic sample: the routes and hostnames are a
banking demo's. Read it for the shape of an `extAuthz` policy and its `context` map, then
write your own routes.

```yaml
policies:
  extAuthz:
    host: coaz-pep:9191
    failureMode: deny
    includeRequestBody:            # the PEP inspects JSON-RPC and payment bodies
      maxRequestBytes: 65536
      allowPartialMessage: true
    protocol:
      grpc:
        context:
          pep_label: "PEP#1 (MCP edge)"
          style: "mcp"
          require_token: "true"
          mcp_upstream_url: "http://my-mcp-server:8090/mcp"   # enables COAZ
```

## Istio

[`istio/coaz-pep.yaml`](istio/coaz-pep.yaml) has the deployment, service,
`AuthorizationPolicy` and an `EnvoyFilter`. One piece cannot be expressed as a CRD — the
extension provider goes in the `istio` ConfigMap:

```yaml
# kubectl -n istio-system edit configmap istio   (under data.mesh)
extensionProviders:
  - name: coaz-pep
    envoyExtAuthzGrpc:
      service: coaz-pep.authz.svc.cluster.local
      port: 9191
      includeRequestBodyInCheck:
        maxRequestBytes: 65536
        allowPartialMessage: true
```

Then `action: CUSTOM` with `provider.name: coaz-pep` on the workloads you want guarded.

**The trap:** `AuthorizationPolicy` has no field for `context_extensions`, so without more
work every request reaches the PEP with the defaults — `style=rest`, `require_token=false`,
no COAZ. Fine for a plain REST service whose tokens a `RequestAuthentication` already
validates; **not** fine for an MCP edge, where `style` and `mcp_upstream_url` have no
sensible default. Either patch them in with the `EnvoyFilter` in the sample, or give the
MCP edge its own provider pointing at its own `coaz-pep` Service.

Note that `rules` on a CUSTOM policy select *which requests get sent for a decision*. They
do not decide anything. Narrowing them is how you exempt `/healthz`, not how you authorise.

## Plain Envoy

Same filter, configured directly:

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      failure_mode_allow: false        # fail closed
      with_request_body: { max_request_bytes: 65536, allow_partial_message: true }
      grpc_service:
        envoy_grpc: { cluster_name: coaz_pep }
        timeout: 2s
```

Per-route knobs go in `ExtAuthzPerRoute.check_settings.context_extensions`, exactly as in
the Istio `EnvoyFilter` sample.

## Knobs

Read from `context_extensions` on every request:

| Key | Default | Meaning |
| --- | --- | --- |
| `pep_label` | `coaz-pep` | Identifies this PEP in challenges and logs |
| `style` | `rest` | `rest` (resource server) or `mcp` (MCP edge) |
| `require_token` | `false` | Deny without a readable access token |
| `require_dpop` | `false` | Enforce the `cnf.jkt` sender-constraint (RFC 9449) |
| `require_user_login` | `false` | Deny without a valid `X-User-Token`, with a login challenge |
| `stepup_scope` | — | Scope demanded for `stepup_action` |
| `stepup_action` | `make_payment` | Action the step-up applies to |
| `mcp_upstream_url` | — | Set to enable COAZ: where to discover `tools/list` |
| `coaz_defaults` | `false` | Apply the binding's default mappings to undeclared methods |
| `legacy_subject_identity` | `true` | Also send the non-standard `subject.identity` beside AuthZEN's `subject.id`. Set `"false"` once policies read `subject.id` — see [core/README.md](../../core/README.md#migrating-subjectidentity---subjectid) |
