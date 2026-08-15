# runtimeexecutor

`runtimeexecutor/v1beta1` is the provider-neutral execution SPI for an already
authorized StackKits Architecture v2 Apply grant.

The control plane owns authorization, executor registration, retries, durable
state, and product policy. This package only seals and validates the immutable
grant projection, transports content-addressed artifact bytes without workspace
paths, invokes one selected adapter safely, checks exact runtime and health
outcomes, and derives a canonical result digest.

Runtime targets retain their exact site, node, workload, paired image ref and
immutable image digest, daemon, and
artifact references. Provider-owned runtimes additionally retain the exact
versioned owner adapter identity; module runtimes cannot carry that authority.
Workload targets using `selected-paas` must also retain one exact runtime
adapter binding: adapter ID, provider/module versions and contract hashes,
separate companion-agent module identities, and only the content-addressed
contract-handoff artifacts owned by those exact modules. Executable workload
artifacts and adapter handoffs are different execution classes and cannot be
substituted for one another. This proves the upstream Coolify/Komodo-style
selection without carrying an endpoint, credential, provider resource,
transport configuration, host permission, lease, or lifecycle operation.
Health targets retain both their materialized requirement ID and their logical
source contract ref, so a control plane never reconstructs one from the other.
Executable route Health additionally binds one exact runtime requirement, route,
backend pool, Site/node placement, and a closed address-free HTTP or TCP probe.
The probe can carry only protocol, port, bounded timeout, and the protocol's
fixed method/path/status policy; URL, host, redirect, credential, TLS identity,
and trust material are not representable. This lets the authenticated runtime
owner resolve and observe its own internal target without turning StackKits into
endpoint or network authority.
Optional Home access bindings retain only the exact StackKits requirement,
Site/capability/target-node scope, contract hashes, opaque external binding and
fabric refs, and a finite maximum-24-hour validity window. Every binding names
and is referenced by exactly one runtime requirement, carries a canonical
projection hash, participates in the sealed request digest, and is checked
against the actual invocation clock immediately before the adapter call. The
control plane must capture one UTC instant for authorization and call
`InvokeAt` with that same instant; the serialized authorization timestamp is
only a digest-bound consistency value and is never accepted as freshness proof
on its own. The
contract has no transport, endpoint, address, credential, provider
resource/account/region, discovery, lease, generation, or lifecycle field.
Optional Cloud backup-target bindings follow the same fail-closed envelope
without reusing Home access authority. They bind one exact runtime requirement,
Site, node set, `offsite-object-backup` capability and contract hash to opaque
target and custody-attestation refs. The shared projection has its own
content hash and maximum-24-hour validity window, is included in the sealed
request digest, and is rechecked against the actual `InvokeAt` instant before
the adapter runs. Buckets, endpoints, credentials, accounts, regions, provider
resources, leases, transports, backup-target lifecycle, and provider selection
are not representable.
Render-instance artifacts bind their exact provider,
module, unit, instance, logical output, site, and node identity and are
referenced exactly once. Plan-owned artifacts bind both owner reference and
owner contract hash to the exact plan digest and are never runtime-referenced.
Neither carries a workspace path. A daemon's
canonical absolute runtime socket is the only path-shaped contract value. The
verified result additionally binds the complete sealed request digest.

`ExecutionChannelRequest` and its factory/admission interfaces bind one opaque
channel to an exact single-Site/single-node Runtime+Health closure. A remote
admission can return its authenticated transport executor without constructing
local Operations; the shared contract still carries no endpoint, credential,
provider resource, lease, generation, discovery, or retry policy.

It intentionally contains no provider SDK/configuration, credentials, database,
network transport, StackSpec type, workspace path, discovery, or policy.
