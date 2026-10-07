<!--
PR title: must start with `fix:`, `feat:` or `major:` (it becomes the squash commit
message on main, which drives the automated version bump). See CONTRIBUTING.md.

Security vulnerabilities: do not open a public PR. See SECURITY.md.
-->

## Summary

<!-- What does this change and why? Link related issues (e.g. "Closes #123"). -->

## Affected crates

- [ ] `ttk-core`
- [ ] `ttk-ra-server`
- [ ] `ttk-ra-client`
- [ ] `ttk-relay`
- [ ] `ttk-terminal`
- [ ] Deployment / build (`Dockerfile`, `scripts/`, `deploy/`, workflows)
- [ ] Docs only

## Release impact

- [ ] `fix:` — bug fix (patch)
- [ ] `feat:` — new feature (minor)
- [ ] `major:` — breaking change (major); describe the migration below

## Security impact

<!--
Does this touch TLS/QUIC setup, RA-TLS certificate generation, attestation providers,
evidence appraisal / EnclaveCertVerifier, HPKE sealing, the vsock transport, or
dependencies? If so, explain what changes for the trust model. Otherwise write "None".
-->

## Testing

<!-- How was this tested? New or updated tests, manual runs, TEE hardware used (Nitro / SEV-SNP / TDX) or mock only. -->

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass
- [ ] `cargo test --workspace --all-features` passes
- [ ] Builds with the feature combinations I touched (features are additive)
- [ ] `cargo deny check --all-features` passes (if dependencies changed)
- [ ] Public items have `//!` / `///` docs
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (if user-visible)
- [ ] Book in `docs/` updated (if behavior it describes changed)
- [ ] I did not bump the version in `Cargo.toml` (CD does that)
