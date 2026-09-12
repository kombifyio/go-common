# Changelog

## [0.6.1] - 2026-09-12

- Publish the provider-neutral authentication, denial, identity, HTTP, native-client, OIDC, role, runtime-execution, and tool-auth packages as `github.com/kombifyio/go-common`.
- Define the supported public module boundary as the 13 reviewed package paths plus the required internal `referenceid` implementation.
- Remove the historical `edgeauth`, `fga`, `observability`, and `servicecall` packages from the public module because they belong to Kombify SaaS composition.

#### Compatibility

Pin `v0.6.1` for the supported public packages. Consumers of the four removed historical packages must migrate to product-owned composition boundaries before upgrading.

- Correct release authentication and authenticated plan finalization for the first public module publication.
