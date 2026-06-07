// Package ranges provides bundled IP ranges for well-known reverse-proxy
// providers, for use as the trustedRanges argument to
// realclientip.NewRightmostTrustedRangeStrategy.
//
// SECURITY: these lists are static snapshots committed to the repository. They
// WILL drift from the providers' live ranges over time, and a stale list used
// with RightmostTrustedRangeStrategy is a security risk in both directions:
//
//   - A range the provider has since RELEASED may be reassigned to a third
//     party, who would then be wrongly trusted as your proxy. An attacker on
//     that range could spoof the client IP.
//   - A range the provider has since ADDED is treated as untrusted, so a
//     legitimate proxy hop is mistaken for the client, yielding a wrong or
//     empty result.
//
// For correctness-critical use, fetch the ranges at runtime from the provider
// (the Cloudflare API, or the AWS "origin-facing" managed prefix list), or
// verify proxy identity by a means stronger than IP (e.g. authenticated
// origin pulls). A scheduled CI job (.github/workflows/ranges-drift.yml)
// refreshes these snapshots, but there is no freshness guarantee at any given
// commit; check git history for when each file was last updated.
package ranges

//go:generate go run ./internal/gen
