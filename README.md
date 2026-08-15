# kombify Go Common

Public, provider-neutral Go utilities used by the kombify TechStack
self-hosted runtime and its native clients.

This mirror contains only the Apache-2.0 packages required by the public
TechStack source tree. It owns reusable authentication, identity, HTTP,
native-client, observability, and runtime-envelope utilities. It does not own
provider credentials, provider drivers, hosted commerce, product state, or
orchestration policy.

## Packages

- `authflow`, `authlocal`, and `authsession` — browser and local session flows
- `cloudlogin` — fail-closed optional hosted-login gate
- `edgeauth`, `fga`, `identity`, and `role` — identity and authorization helpers
- `httputil` and `servicecall` — HTTP envelopes and optional service auth
- `nativeclient/*` and `toolauth` — device/profile flows used by native clients
- `oidcclient` — provider-neutral OIDC discovery, PKCE, and verification
- `observability` — optional Sentry instrumentation; empty configuration is a
  no-op
- `runtimeexecutor` — provider-neutral execution envelope validation

Self-hosted callers keep hosted integrations disabled by configuration. This
repository contains no deployment workflow, container image, or provider
implementation.

## Development

```bash
go test ./...
go build ./...
```

The module path is `github.com/kombifyio/go-common`. Consumers should pin a
published version when the public repository is created.

## License

Apache-2.0. See [LICENSE](LICENSE).
