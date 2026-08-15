// Package oidcclient provides a provider-neutral OIDC client used across all
// kombify Go services (Simulate, StackKits-Server, TechStack).
//
// The package is split into four pieces that compose:
//
//   - [Verifier] — verifies RS256 ID tokens against issuer + audience using a
//     cached JWKS endpoint.
//   - [Provider] / [Registry] — wraps a [Verifier] together with the OAuth2
//     authorization-code endpoints of a single issuer (Pocket ID, Auth0,
//     PocketBase-OIDC bridge, generic OIDC).
//   - [CodeExchanger] — exchanges an authorization code (with optional PKCE
//     verifier) for an ID token.
//   - [Discover] — best-effort fetch of `.well-known/openid-configuration`.
//
// Identity bridge: [IdentityFromClaims] converts an OIDC [Claims] into a
// [github.com/kombifyio/go-common/identity.Identity] so that
// downstream middleware can keep using the existing identity context plumbing.
//
// Self-hosted vs SaaS: callers configure the same client with a different
// Issuer URL — Pocket ID for the self-hosted default, Auth0 for SaaS, the
// PocketBase OIDC bridge for legacy operators. There are no SaaS-specific
// branches in this package.
package oidcclient
