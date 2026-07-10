# Leitwacht malicious-packages

A public, **permissively-licensed** ([CC0-1.0](./LICENSE)) feed of malicious npm
packages detected by [Leitwacht](https://leitwacht.eu), in
[OSV](https://ossf.github.io/osv-schema/) format — a CC0 OSV **source database**,
consumable by `osv-scanner` / `deps.dev` and ingestible by `osv.dev`.

Released under CC0 so it can be absorbed by OSV and embedded anywhere, with no
attribution or licensing burden on consumers.

## What's in here

Records live under `osv/<year>/<id>.json`, where the id is our own
**`LWA-YYYY-NNNN`** ("Leitwacht Advisory") — so a record's path is derivable from
its id alone. A root [`index.json`](./index.json) maps every id to its file,
package, and (once OSV assigns one) the canonical `MAL-YYYY-NNNN`, which we import
into the record's `aliases`. Each record permalinks to its writeup at
`https://threatintel.leitwacht.eu/d/<id>`.

Records are **high-precision by construction**: a package is named here only after
its unwanted behaviour is independently verified from the package source itself.
The feed is **going-forward only**, and records are **sticky** — once a package
has an `LWA-` record it stays, removed only by an upheld
[takedown](https://threatintel.leitwacht.eu/policy#dispute) (marked `withdrawn`,
never silently dropped).

**Scope — anything you would not want installed.** Each record carries a
`database_specific.leitwacht.category` so you can tell *what* it is:

- `malware` — attacker-embedded malicious code (credential/wallet theft, backdoor,
  dropper, install-time RCE);
- `dependency_confusion` — a name/scope squat whose payload is delivered from an
  untrusted external source (a fetched tarball or a named-malicious dependency),
  not embedded in the package itself;
- `pua` — riskware (proxyware, remote-binary-exec, miners, aggressive telemetry);
- `research_poc` — a security-research / proof-of-concept package.

All of these exhibit behaviour you would not want running in your build — that is
the bar. We describe each **factually** and never frame a research PoC as criminal
malware. CWE tags are category-accurate: `malware` carries **CWE-506** (Embedded
Malicious Code); `dependency_confusion` carries **CWE-829** (Inclusion of
Functionality from an Untrusted Control Sphere — the code is pulled from an
external dependency/tarball, not embedded here); `pua` and `research_poc` carry no
CWE. Note
that OSV consumers block *every* record regardless of category; the label is for
human clarity, not a severity downgrade.

Deliberately **excluded**: empty-shell / no-code namespace reservations (nothing
executable ships, so nothing can happen on install) and accidental credential
leaks by otherwise-benign publishers (a real exposure to rotate — not a package
that attacks you). Every gate-passing detection is published — including ones OSV
already covers: we publish our own independent first-party record and import OSV's
`MAL-` id into `aliases` as a cross-reference. OSV coverage is never a reason to
omit a record; once published, a record is sticky and stays.

Published text is sanitized: leaked secrets removed, IOCs defanged, no personal
data.

## Using it to block installs

The prebuilt osv-scanner offline DB is published as a rolling **Release** asset
(kept out of git so the repo stays lean). Fetch it and gate your lockfile offline:

```sh
base=https://github.com/leitwacht/malicious-packages/releases/download/db-latest
mkdir -p leitwacht-osv/osv-scanner/npm && cd leitwacht-osv/osv-scanner/npm
# download the latest offline DB + its signature:
curl -sSLO $base/all.zip
curl -sSLO $base/all.zip.cosign.bundle

# VERIFY it's genuinely ours before trusting it (keyless Sigstore — there is no
# key to distribute; the signature is bound to our exact build workflow identity):
cosign verify-blob all.zip \
  --bundle all.zip.cosign.bundle \
  --certificate-identity \
    'https://github.com/leitwacht/malicious-packages/.github/workflows/build-offline-db.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

# then scan offline (osv-scanner reads only all.zip, never the osv/ tree):
cd - && osv-scanner scan source --offline --local-db-path ./leitwacht-osv -L package-lock.json
```

The DB is signed on every rebuild with [Sigstore](https://www.sigstore.dev/)
keyless signing; a `sha256sum -c all.zip.sha256` is also published for a plain
integrity check.

To browse or audit the raw detections, `git clone` the repo — the JSON records
under `osv/` are the source of truth; the Release asset is just those records
packed for osv-scanner.

Or — once this feed is ingested as an OpenSSF source — you get our detections
automatically through `osv.dev`, `osv-scanner`, GitHub/Dependabot, and any tool
that consumes OSV. No Leitwacht integration required.

## Disputes / takedowns

Wrongly flagged? Detection is research, published as-is. Request a correction at
<https://threatintel.leitwacht.eu/policy> (or open an issue). Upheld disputes are
**withdrawn** (the OSV `withdrawn` field), not silently deleted — the audit trail
is preserved and consumers stop enforcing it.
