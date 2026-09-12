# kombify Go Common

Public, provider-neutral Go utilities used by the kombify TechStack
self-hosted runtime and its native clients.

This mirror contains the provider-neutral public library surface used by the
TechStack local/self-host runtime. It owns reusable authentication, denial,
identity, HTTP, native-client, and runtime-envelope utilities.
It does not own provider credentials, provider drivers, hosted commerce,
product state, or orchestration policy.

## Packages

- `authflow`, `authlocal`, and `authsession` — browser and local session flows
- `cloudlogin` — fail-closed optional hosted-login gate
- `denial` — stable client-facing denial envelopes
- `identity` and `role` — provider-neutral identity helpers
- `httputil` — HTTP envelopes
- `nativeclient/*` and `toolauth` — device/profile flows used by native clients
- `oidcclient` — provider-neutral OIDC discovery, PKCE, and verification
- `runtimeexecutor` — provider-neutral execution envelope validation

Self-hosted callers keep hosted integrations disabled by configuration. This
repository contains no SaaS edge authentication, FGA client, company
observability adapter, service-to-service authentication, container image,
provider implementation, product state, or provider credentials.

## Development

```bash
go test ./...
go build ./...
```

The module path is `github.com/kombifyio/go-common`. Consumers must pin a
published version.

## License

Apache-2.0. See [LICENSE](LICENSE).
