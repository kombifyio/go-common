# ClientConnectionProfile v1 fixtures

Copied from the workspace SSOT
`kombify-workspace/internal/standards-enforcement/client-connection-profile-fixtures/`
(gate: `mise run client-foundation:check`). Keep byte-identical when the SSOT
changes.

`invalid-unregistered-capability.json` is intentionally NOT copied: capability
registry membership is a server/workspace-side gate
(`client-capability-registry.v1.json`); this client package validates
capability syntax only.
