# Releasing

How a release of this fork is made, what its files look like, and how to check a download. A
future change that adds hash checking to the client's updater should read this first.

## Asset contract

Each release has these assets:

- One installer per platform, named `iShareaza_<version>_<Win32|x64>_Release_<YYYY-MM-DD>.exe`.
- `SHA256SUMS.txt`, in `sha256sum` format: lowercase hex, two spaces, the file name.

The update check finds the installer by the word `Release` and the platform in its URL. Names must
keep that form.

Every release raises the fourth number of the version. A release is never made again under the
same number.

## Hashes for a future client check

Each asset has a `digest` field in the releases API, in the form `sha256:<hex>`. GitHub records it
for every asset uploaded since June 2025. A client would read it from `releases/latest`, in
`assets[]`. The client already parses that response.

The digest is guaranteed to describe the file that is served only for a release published under
immutability. So previ.8 is the first release a hash-checking client could rely on.

A hash check protects against a corrupted or substituted download, not a compromised GitHub account.
A compromised account could publish a new release with matching digests. The attestations are for
people. A client would not check Sigstore bundles.

## Repository settings

Set through the REST API, and recorded here so they can be checked later.

| Setting | How | Effect |
|---|---|---|
| Immutable releases | `PUT /repos/Prev-I/Shareaza/immutable-releases` | On publish, the assets and the tag are locked and GitHub signs a release attestation. Title and notes stay editable. Earlier releases are unaffected. A deleted immutable release's tag can never be used again. |
| Tag ruleset `release-tags` | `POST /repos/Prev-I/Shareaza/rulesets`, target `tag`, include `refs/tags/v*`, rules `deletion`, `update`, `non_fast_forward`, no bypass actor | Release tags cannot be deleted or moved. Creating them stays open. |
| Issues | `PATCH /repos/Prev-I/Shareaza` with `has_issues` set to true | Users can report problems. |
| Private vulnerability reporting | `PUT /repos/Prev-I/Shareaza/private-vulnerability-reporting` | Security reports arrive privately, as [SECURITY.md](../SECURITY.md) asks. |

The ruleset has no bypass actor. To move or delete a release tag, the owner switches the ruleset off in Settings first, then switches it on again.

## Releasing

1. Push the annotated tag `v<version>-previ.N` on `main`.
2. `release.yml` builds both installers, attests them and creates a draft release.
3. Run the oracles on the draft's build. This is the last gate: after publication nothing can be
   replaced.
4. Write the release notes. The first paragraph is plain ASCII, about 330 characters. Use no percent
   sign anywhere: older clients log the notes as a printf format and show them raw. Review the notes
   for any disclosure of the security audit's withheld detail.
5. The owner publishes the release.
6. `verify-release.yml` must pass (see below).
7. Run the oracles against the release, then open the kits pull request.

If the build or the draft is bad before publication: switch the ruleset off, delete the draft and
the tag, fix it through a pull request, tag again, switch the ruleset on. Nothing was published,
so the tag name is not lost.

A draft that is never published leaves its attestation behind. It attests a file that was really
built, so it is harmless, but its installers must not be handed out.

## After publication

A defect found after publication means the next previ.N, never a replaced asset. Add a note to
the release that names the fixed release.

`verify-release.yml` runs when a release is published, and by `workflow_dispatch` with the input
`tag`. It downloads the installers and `SHA256SUMS.txt`, checks the files against the manifest and
against each asset's `digest`, checks each installer's build attestation, and runs
`gh release verify` and `gh release verify-asset`. It retries each `gh` check for about 5 minutes,
because attestations and digests can appear shortly after publication.

A failure is a signal, not a verdict. Look at which check failed:

- The files are wrong: make the next `previ.N` and add a note to the release.
- The tooling or the timing is at fault: run the workflow again by `workflow_dispatch` with the
  tag.

A dispatch against a draft fails at the API lookup, because the API does not return a draft by
tag. Run it against a published release only.

## Verifying a download

Each release body lists these checks. Replace `<file>` with the installer and `<tag>` with the
release tag.

- Built by this repository's release workflow:
  `gh attestation verify <file> --repo Prev-I/Shareaza --signer-workflow Prev-I/Shareaza/.github/workflows/release.yml`
- Unchanged since publication:
  `gh release verify-asset <tag> <file> --repo Prev-I/Shareaza`
- Without `gh`: `Get-FileHash <file> -Algorithm SHA256`, compared with `SHA256SUMS.txt` or the
  sha256 GitHub shows beside each asset.

Use `gh` 2.81.0 or later. For `gh attestation verify` never use a version below 2.67.0: older
versions could report success when no attestation exists (CVE-2025-25204).
