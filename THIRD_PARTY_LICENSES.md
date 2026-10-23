# Third-party licenses

A4A itself is MIT-licensed (see `LICENSE`). The following third-party components are
distributed with or used by parts of this repository under their own terms.

## What each distribution contains

| Distribution | Contents and licensing scope |
| --- | --- |
| Public source repository | A4A source, the MIT relay and explicitly included third-party material. Preserve applicable author notices, licenses and modification notes for material actually copied. A dependency requirement or Dockerfile does not itself distribute the dependency's binary/image bytes. |
| A4A Python wheels | The retained SDK, MCP, project-agent and notary wheels contain their own package namespaces and license files. External packages are declared in `Requires-Dist` and installed separately; they are not bundled in those wheels. Recheck actual members if packaging changes. |
| Ready-to-run Docker images or relay binaries | Images include the operating-system packages and installed libraries; the relay executable also links Rust dependencies. Review notices, applicable source availability and replacement/relinking conditions for these exact copies, including older versions retained in image layers. |

These boundaries describe packaging, not a completed provenance review or a
change of license. The presence of GPL tools in an image does not automatically
make independent A4A code GPL: the GPL distinguishes an aggregate of separate
works from a combined program. Linking and copied code require their own review.
See [GPL-3.0, sections 5–6](https://opensource.org/license/gpl-3.0) and
[LGPL-3.0, section 4](https://opensource.org/license/lgpl-3-0).

For an online GPL-3.0 object-code distribution, the planned route is equivalent
access to exact corresponding source with clear directions beside the download
(section 6(d)). A generic upstream homepage is not proof that the required
source is available. Verify the selected versions, patch/build inputs, access
and retention before distributing images. Do not assume that a written-offer
route for physical distribution applies unchanged to an online image registry.
GPL-2.0 and other license versions need their own applicable distribution route.
The current registry-scoped source bundle below covers only its listed groups;
it does not certify the whole Docker-image contents.

## a4a-relay (relay/)

`relay/` is the Rust A4A relay node (`relay/README.md`), distributed under the MIT License
(`relay/LICENSE` and repository `LICENSE`).

## NIP-44 official test vectors (sdk-python/tests/)

`sdk-python/tests/nip44_vectors.json` is an unmodified copy of the official
NIP-44 test vectors. Its SHA-256 is
`269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040`,
as published by [NIP-44, Tests and code](https://github.com/nostr-protocol/nips/blob/a79e21d90fce5465b50ef385dd368bba99ec4a0b/44.md#tests-and-code).

The byte-identical copy at
[`javascript/test/nip44.vectors.json`](https://github.com/paulmillr/nip44/blob/671a1f04bcfacaf125b0db68adc45bc9ce0e763b/javascript/test/nip44.vectors.json)
is under the ancestor [`javascript/LICENSE`](https://github.com/paulmillr/nip44/blob/671a1f04bcfacaf125b0db68adc45bc9ce0e763b/javascript/LICENSE),
the complete Unlicense text. That text is preserved verbatim in
[`sdk-python/tests/nip44_vectors.LICENSE.txt`](sdk-python/tests/nip44_vectors.LICENSE.txt)
(SHA-256 `f0510d3b9d1223c45e8fdd2b49270ec8734fff491c7f7d1b948ee70162e1ceff`).
The upstream `javascript/package.json` at that same revision separately declares
MIT. This metadata disagreement is recorded rather than silently resolved by
A4A's own MIT declaration; no fixture-specific standalone grant is claimed.

The [NIPs licensing statement](https://github.com/nostr-protocol/nips/blob/a79e21d90fce5465b50ef385dd368bba99ec4a0b/README.md#license)
declares all NIPs public domain. It is a statement about the specifications,
separate from the copied fixture's source and accompanying grant above. Other
implementations in the vector repository retain their own licenses.

## OpenTimestamps (notary/)

The time-notary sidecar (`notary/`) imports the separately installed Python package
[`opentimestamps`](https://github.com/opentimestamps/python-opentimestamps).
The locally cached 0.4.5 wheel's `opentimestamps-0.4.5.dist-info/LICENSE` explicitly grants
LGPL version 3 or any later version (LGPL-3.0-or-later); its metadata says `License: LGPL3`
and classifies it as LGPLv3+. The [upstream LICENSE](https://github.com/opentimestamps/python-opentimestamps/blob/master/LICENSE)
contains that project-specific grant followed by the LGPL-3.0 text. This is not A4A's
license: A4A-original notary code uses the repository's MIT license, reproduced in
`notary/LICENSE`.

The notary's Python distributions contain A4A code and declare the OpenTimestamps
dependency; they do not vendor the library. `notary/licenses/` now carries THREE files: the reference LGPL-3.0 and GPL-3.0 texts,
and `python-opentimestamps-LICENSE.txt` — the complete upstream LICENSE copied verbatim
from the `opentimestamps-0.4.5.dist-info` of the installed wheel, including the
project-specific grant that precedes the LGPL text.

That third file was missing until 08.09.2026, and its absence mattered specifically
because `notary/Dockerfile` DOES bundle the library. The image installs the exact
`opentimestamps` artifact selected by `notary/requirements.container.lock` and copies
`notary/licenses/` to `/app/licenses`. So an image built from this repository distributed
the library while shipping only generic licence texts, without the upstream grant and
notice. Source-only distribution of the Python packages does not carry that obligation;
the image does. The earlier version of this document named the gap honestly and left it
open — it is now closed for the source tree.

The source-tree checks alone do not verify a built image. For a concrete release
candidate, build the four wheels and the relay, MCP, and notary images, then run
`scripts/generate-release-inventory.py` with all four `--wheel` paths. The command refuses
a dirty Git worktree by default, binds every artifact to its SHA-256 or immutable image
ID, and atomically writes three SPDX 2.2 image SBOMs plus the target-filtered locked Rust
dependency graph under `build/release-inventory/`.

A binary/container candidate that actually bundles OpenTimestamps needs a separate
artifact review: preserve the full upstream LICENSE and copyright notices, include the
GPL/LGPL texts, and check the applicable source availability and library replacement
conditions against that exact distribution. A sidecar process or an ordinary Python
import is not, by itself, proof of LGPL compliance. This records packaging facts and
release checks, not a legal guarantee.

## Python and Rust dependencies

Direct Python dependency requirements are declared in `sdk-python/pyproject.toml`,
`mcp-server/pyproject.toml`, `agent-service/pyproject.toml` and `notary/pyproject.toml`.
The library metadata deliberately uses compatible version ranges for downstream users.
Release containers are narrower: `mcp-server/requirements.container.lock` and
`notary/requirements.container.lock` pin their complete Linux/Python 3.11 runtime graphs
with SHA-256 hashes, while `scripts/container-build-requirements.lock` does the same for
the isolated wheel-building stage. A separate hash-locked pip bootstrap is used
before installation. The image base is pinned by digest. Regenerate all four
locks in that same Linux environment with:

```console
python scripts/compile-container-locks.py
```

Review the dependency diff, rebuild both images, run their tests and `pip-audit`, and
regenerate the artifact inventory before accepting an update. The `.in` files are the
human-maintained roots; the `.lock` files are generated release inputs.

The final Python images omit pip, setuptools, wheel and ensurepip. They copy the
checked preparation filesystem into a new final stage, rather than distributing
the installers in inherited layers. This removes setuptools' vendored autocommand
from these images too. Validate the actual saved image layers and regenerate its
SBOM; an installer-free image is not by itself a complete dependency/license audit.

### Artifact-bound review of scanner `NOASSERTION` entries

Syft does not always translate an installed package's license metadata into SPDX. A
`NOASSERTION` value is therefore neither a license conclusion nor evidence that a package
has no license. `scripts/release-license-review.json` records the review of the exact
packages currently present in the release images. Every entry is bound to the image name,
package version, in-image evidence path, and SHA-256 of that evidence:

| Image | Package versions | Reviewed license expression |
|---|---|---|
| Relay, MCP, notary | debian-archive-keyring 2025.1 | GPL-2.0-or-later AND LicenseRef-Public-Domain |
| Relay, MCP, notary | tzdata 2026c-0+deb13u1 | LicenseRef-Public-Domain |
| notary | opentimestamps 0.4.5 | LGPL-3.0-or-later |
| notary | pycryptodomex 3.23.0 | BSD-2-Clause AND LicenseRef-Public-Domain |
| notary | python-bitcoinlib 0.12.2 | LGPL-3.0-or-later |

The inventory generator fails if a new `NOASSERTION` appears, a reviewed version
disappears or changes, or the in-image evidence hash changes. It records both the raw
scanner count and the separately reviewed conclusions; it does not rewrite the scanner's
SPDX document or pretend that a human conclusion came from Syft. MCP and notary also copy
the applicable Python dependency notices to `/app/licenses` for direct inspection.

For the pinned PyCryptodomex 3.23.0 native wheel, `notary/licenses/` also carries
`pycryptodomex-3.23.0-native-NOTICES.txt`, `pycryptodomex-LICENSE-libtom.txt`, and
`CC0-1.0.txt`. The first preserves 24 complete source comment blocks with all
source paths, including individual copyright notices and the SipHash declaration.
The LibTomCrypt text comes from the exact sdist's `Doc/LEGAL/copy/LICENSE.libtom`;
the CC0 legal text comes from Creative Commons' legal-tools data repository.
These files supplement the wheel's top-level `LICENSE.rst`; the normal Docker
copy and runtime selection preserve them in `/app/licenses` in a new build.
They are tracked release inputs and require a new image/inventory acceptance;
an older image's validation does not establish that it contains these additions.
The source list conservatively includes preprocessor alternatives. It does not
assert full build provenance, exact static-link closure, or legal acceptance.
The source is the [PyCryptodomex 3.23.0 sdist](https://pypi.org/project/pycryptodomex/3.23.0/#files),
SHA-256 `71909758f010c82bc99b0abf4ea12012c98962fbf0583c2164f8b84533c2e4da`.
The CC0 text is [Creative Commons' COPYING at commit a0dac18](https://github.com/creativecommons/cc-legal-tools-data/blob/a0dac18d1a773b4cdb7d8dd5d9bf4efab7901030/COPYING).

The LGPL components remain separate Python distributions or shared system libraries, not
code copied into A4A source. A distributed candidate must still preserve the notices and
complete license texts, keep replacement/relinking practical, and provide corresponding
source or a durable source offer as applicable. The registry records evidence and release
actions; it is not a legal opinion or automatic authorization to publish.

### Replacing LGPL libraries in a container

Recipients may modify the LGPL libraries and debug their modifications by
replacing the separately installed libraries. The working release route is the
shared-library option in [LGPL-3.0 section 4(d)(1)](https://opensource.org/license/lgpl-3-0)
or [LGPL-2.1 section 6(b)](https://opensource.org/license/lgpl-2-1), as applicable
to the actual component. Required notices, license texts, corresponding source
and any applicable installation information accompany that route.

For the notary, prepare a directory containing modified `opentimestamps/` and
`bitcoin/` packages from the exact source distributions in the corresponding-source
bundle. Preserve their notices and identify your changes. Set `NOTARY_IMAGE` to
the immutable image identity matching your artifact inventory. A Linux shell
can inspect the selected library origins without starting the notary:

```console
docker run --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,source=$(pwd)/library-overrides,target=/opt/library-overrides,readonly" \
  --env PYTHONPATH=/opt/library-overrides --entrypoint python \
  "$NOTARY_IMAGE" -B -c \
  'import opentimestamps.core.op, bitcoin.core.serialize; print(opentimestamps.core.op.__file__); print(bitcoin.core.serialize.__file__)'
```

Both paths must point into `/opt/library-overrides`. For an actual notary run,
retain that mount and environment alongside your normal configuration and state
volumes, using the image's normal entry point. The release image omits pip; the
mounted source-package route works without installing a package manager inside
it. Python's `-I` isolated mode ignores `PYTHONPATH`; the normal image entry point
uses regular Python import resolution.

For native shared libraries, a recipient-provided directory can be mounted at
`/opt/library-overrides` with `LD_LIBRARY_PATH=/opt/library-overrides`. Libraries
must retain compatible SONAMEs, architecture, interfaces and required symbol
versions. Run the application's relevant acceptance checks with those libraries;
`LD_DEBUG=libs` can confirm loader selection during a local diagnostic run. The
relay uses dynamic glibc linking. GMP is used by separate system tools in the
images, rather than linked into the relay executable.

The retained engineering checks exercise modified OpenTimestamps and
python-bitcoinlib with unchanged notary Merkle-tree code, and a GMP build with
Debian patches and a changed version value in all three images. Arithmetic
and hash results remain correct. A metadata-only glibc variant demonstrates
external loader selection; it does not demonstrate rebuilding glibc. These
bounded checks establish the tested replacement mechanisms, not compatibility
with every future library modification or complete licensing acceptance.

### Reproducible corresponding-source bundle

`scripts/release-source-bundle.json` maps every GPL/LGPL occurrence in the
artifact-bound review to exact upstream source files, HTTPS origin URLs, byte sizes, and
SHA-256 hashes. The mapping is deliberately per image and installed version: a new,
removed, or changed copyleft package makes the build fail instead of silently inheriting
an old source archive. The current mapping covers five reviewed copyleft occurrences
plus 222 installed Debian package occurrences across relay, MCP and notary, with
168 exact source files across 55 groups. Fifty-two Debian source coordinates are
provided conservatively where the installed package's SBOM expression includes
GPL/LGPL terms; this is not normalization of mixed licenses or a conclusion that
every file has the same grant. The additional known-license packages have
separate bindings to the image ID, exact SBOM bytes, declared license, binary/source
PURL and full installed copyright notice. They do not create artificial unknown-license
review entries. This is partial coverage, not every copyleft package in the SBOM;
complete container acceptance remains
a separate release gate. Older Bookworm review/source packages remain paired with
their original images and retain their historical binary-to-source mappings.

After generating a clean release inventory and retaining its exact installed notices,
create the local bundle with:

```console
python scripts/build-license-source-bundle.py --notice-root build/installed-notices
python scripts/build-license-source-bundle.py --verify build/license-source-bundle
```

The builder downloads each source to a temporary directory, verifies its exact size and
SHA-256, checks every Debian `.dsc` `Checksums-Sha256` member against the registry, writes
a human-readable `NOTICE.md` and canonical `manifest.json`, and only then replaces the
output. Previous output and failed staging directories are retained under
`build/.trash/source-bundles/`, with restoration notes and no automatic deletion.
The notice-root layout is `IMAGE/usr/share/doc/PACKAGE/copyright`; the current
additional groups require `relay/usr/share/doc/bash/copyright` and
`relay/usr/share/doc/coreutils/copyright`, plus the exact notices for every other
bound installed package in all three images. Each SBOM must remain beside the inventory.

Retained older layer versions are separate occurrences. The current expanded mapping
does not cover relay's older `libpcre2-8-0=10.46-1~deb13u2`,
`libssl3t64=3.5.7-1~deb13u2` or `openssl-provider-legacy=3.5.7-1~deb13u2` with the
newer installed notices. Rust components, Python dependencies, external-license
exceptions, source authenticity and any replacement/relinking conditions still
need their own complete release acceptance.

The v2 bundle embeds the inventory, bound SBOM and complete notices for offline
verification. `--verify` rejects missing, changed, duplicate, or unexpected source and
evidence files, rechecks binary-to-source coordinates and Debian `.dsc` Source/Version
and member hashes. Historical v1 bundles keep their original coverage and verifier
support; they cannot represent groups requiring v2 evidence. `--cache <directory>`
may supply pre-fetched files, but cached files pass the same checks before they are copied.

Earlier image inventories included setuptools' vendored autocommand and required
its matching source. Keep those older source bundles paired with their original
inventories; the cleaned images and updated registry must not be substituted into
older evidence. Signed Debian `.dsc` files
and upstream detached signatures are preserved where provided. The builder validates the
hash bindings inside `.dsc` files; it does not claim to authenticate their OpenPGP
signatures.

This command creates a local release artifact only. It does not upload, publish, or grant
permission to distribute a release, and passing it remains evidence rather than legal
advice.

### Accessing and building the selected source

For a distributed image, provide its exact inventory and corresponding-source
download beside the image download. Use the source archive and checksum selected
by that release record; an upstream homepage, a mutable image tag or a different
candidate's bundle is insufficient. There is currently no approved public release
URL. The following is the recipient procedure for a prepared evidence package,
not a claim that a download has been published or that every rebuild is accepted.

The public portable support package is named `a4a-public-support.tar.gz`. Obtain its HTTPS
URL and SHA-256 from the selected release record, together with a trusted copy
of the matching verifier scripts. In a Linux shell, set `CORE_EVIDENCE_URL`,
`CORE_EVIDENCE_SHA256` and `A4A_VERIFIER_ROOT` (the absolute source-tree path containing those
scripts). Set `CORE_EVIDENCE_ROOT` to the top-level directory named in the
selected release record; it can differ from the archive filename. Then use a
new empty working directory:

```bash
set -eu
: "${CORE_EVIDENCE_URL:?Set the selected release HTTPS source URL}"
: "${CORE_EVIDENCE_SHA256:?Set its selected SHA-256}"
: "${A4A_VERIFIER_ROOT:?Set the matching verifier source directory}"
: "${CORE_EVIDENCE_ROOT:?Set the selected archive top-level directory}"
mkdir a4a-source-access
cd a4a-source-access
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output a4a-public-support.tar.gz "$CORE_EVIDENCE_URL"
printf '%s  a4a-public-support.tar.gz\n' "$CORE_EVIDENCE_SHA256" | sha256sum --check -
python3 -B "$A4A_VERIFIER_ROOT/scripts/build-release-evidence.py" \
  --verify-archive a4a-public-support.tar.gz
tar -xzf a4a-public-support.tar.gz
python3 -B "$A4A_VERIFIER_ROOT/scripts/build-release-evidence.py" --verify "$CORE_EVIDENCE_ROOT"
python3 -B "$A4A_VERIFIER_ROOT/scripts/build-license-source-bundle.py" \
  --verify "$CORE_EVIDENCE_ROOT/corresponding-source"
PUBLIC_SOURCE_ARCHIVE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_source"]["archive"])' "$CORE_EVIDENCE_ROOT/manifest.json")
python3 -B "$A4A_VERIFIER_ROOT/scripts/build-public-source-archive.py" \
  --verify-archive "$CORE_EVIDENCE_ROOT/public-source/$PUBLIC_SOURCE_ARCHIVE"
```

Stop on any failure. Verify before extracting: the outer archive verifier checks
its file hashes, layout and member types, including nested source bindings.
Successful offline verification binds the received bytes; it does not authenticate
an untrusted release record or extend an expired build/advisory policy.

The public support asset is prepared separately from private acceptance logs.
Its exact archive root and SHA-256 must appear in the selected release record.
It includes source, wheels, saved runtime image evidence, notices and corresponding
source; it is not limited to application source. Do not upload the private owner
review archive as a substitute.

The `supplemental-notices/cpython-source/` directory supplies complete CPython
source and the matching official Docker-library packaging sources for retained
GNU readline and GDBM extension modules. Its manifest binds the exact inventory,
images, module files, library edges, source archives and immutable build recipe.
New notice snapshots require this annex; the ordinary delivered core verifier
checks it. These two archives are additional to the Debian/Python source-bundle
groups and have their own counts. Preserve CPython's full LICENSE and the packaging
repository's LICENSE. The retained registry provenance supplies the publisher's
recipe and pinned Debian build-context claim; this is not independent attestation
authentication or a claim of a bit-identical rebuild.

The package has separate source locations. In the table below, replace
`core-evidence/` with the selected `CORE_EVIDENCE_ROOT/`; the nested public-source
archive name is the `public_source.archive` value in the verified manifest:

| Location under `core-evidence/` | How to use it |
| --- | --- |
| `public-source/<public_source.archive>` | A4A application source, Dockerfiles, lock files and build helpers. Verify this nested archive, then extract it into a separate empty directory. Its root is `a4a-public-source/`. |
| `corresponding-source/manifest.json` and `NOTICE.md` | Select the group whose `covers` entries match the image, package and installed version. It lists each source member's HTTPS origin, size and SHA-256. |
| `corresponding-source/sources/` | Exact listed source members. Debian packages may require a `.dsc`, upstream archive and Debian patch archive together; use the whole group. |
| `supplemental-notices/` | Additional inventory-bound Python/Rust notices, retained-layer sources and provenance/replacement evidence. This supplements the corresponding-source manifest; it is not a universal source or build recipe for every dependency. |

Inspect a selected package's group without changing any files:

```bash
python3 -B - "$CORE_EVIDENCE_ROOT" <<'PY'
import json
import sys
from pathlib import Path
manifest = json.loads((Path(sys.argv[1]) / 'corresponding-source/manifest.json').read_bytes())
matches = [group for group in manifest['groups'] if any(
    item['image'] == 'notary' and item['name'] == 'opentimestamps'
    and item['version'] == '0.4.5' for item in group['covers'])]
if len(matches) != 1:
    raise SystemExit('Expected exactly one source group for the selected package')
for item in matches[0]['artifacts']:
    print(item['filename'], item['size'], item['sha256'], item['url'])
PY
```

For OpenTimestamps and python-bitcoinlib, extract the verified source distributions
into a separate workspace, preserve notices and place the modified `opentimestamps/`
and `bitcoin/` directories in `library-overrides/`. Follow the replacement procedure
above; the Python library route needs no rebuild of A4A or in-image pip installation.

For Debian components, the selected source package's `debian/control` and
`debian/rules` define its build dependencies and package-specific build procedure.
Keep its exact upstream source, Debian patches and configuration together. The
retained GMP experiment applies the Debian patches before `autoreconf -f -i`,
`./configure --disable-cxx --disable-static --enable-shared --disable-assembly`
and `make -j2`; this proves that modified shared-library route, not reproduction
of the Debian binary. A glibc rebuild remains unaccepted.

For A4A's relay image, use `scripts/build-relay-image.py` as described in
[relay/README.md](relay/README.md); direct `docker build relay` lacks the required
authenticated Debian contexts. Python image build inputs are their Dockerfiles,
the pinned base, `scripts/prepare-python-runtime.py` and the hash-locked build and
runtime requirements. A complete image rebuild needs valid build-policy inputs,
the required build environment and artifact acceptance. Do not bypass expiry,
substitute newer dependencies or claim byte-identical binaries from source access
alone. Full build/reproduction acceptance and the public download check remain open.

### Supplemental notice evidence

New notice snapshots require `a4a-release-notice-materials-v4`. The v1/v2/v3
formats remain readable for historical verification; they are insufficient
inputs for building a new snapshot. Native evidence introduced in v3 is retained
in v4, which additionally requires the CPython corresponding-source annex above.
Collect nested Python wheel SBOMs and native-library hashes with:

```console
python scripts/collect-python-notices.py --inventory build/installed-notices/inventory/manifest.json --image mcp --output build/python-notices-mcp
python scripts/collect-python-notices.py --inventory build/installed-notices/inventory/manifest.json --image notary --output build/python-notices-notary
python scripts/prepare-python-native-notices.py --materials build/installed-notices --mcp build/python-notices-mcp --notary build/python-notices-notary --source-cache build/native-source-cache --output build/python-native-overlay
```

The collector runs regular Python metadata/file reads in the exact immutable
image, without network access, write mounts, or importing application modules.
It retains its stopped diagnostic container. Outputs must be new directories;
existing evidence is not replaced. The source cache must contain the archives
whose SHA-256 values appear in the collected upstream SBOMs. Missing archives
or grant texts fail preparation. A crate without dedicated notice files can
use its immutable `.cargo_vcs_info.json` repository commit, with the matching
repository archive present in the cache. No source is downloaded or installed
by these commands.

Apply the generated overlay to a **new unsealed materials copy** and select
that copy through the release policy's `supplemental_notices`. Preserve the
original materials. If reusing a sealed snapshot, omit only its root snapshot
`manifest.json` when copying into staging; retain all nested inventory manifests.
Add `cpython-source/` using the exact source pins in
`scripts/cpython-source-lock.json` and the selected inventory/runtime bindings,
then set the new materials record's schema to `a4a-release-notice-materials-v4`.
Retain the independent pinned-base file measurement alongside the complete
source archives, recipe, licences and publisher provenance. The ordinary
snapshot builder validates v4 and the actual saved runtime payload before
creating its output; changing the schema alone is insufficient.

The verifier derives nested SBOM paths and native-library hashes from installed
`RECORD`, checks every collected metadata/notice/SBOM file against the saved
image payload, and checks complete native ELF and SBOM file sets in site-packages.
Each declared nested component must have source-hash-bound notice evidence;
repository fallbacks must agree with the exact crate-recorded commit. Local
project subcrates can reuse the actual parent grant only when their declarations
agree exactly. Shared source archives are copied once in the overlay.

Native packages without an upstream SBOM remain explicitly listed in
`coverage.python_native.without_sbom` as `requires-file-level-review`. Their
absence cannot be represented as complete dependency coverage. Upstream SBOM
build/excluded/foreign-platform entries are retained conservatively, not claimed
to execute in the image. These checks do not authenticate upstream signatures,
prove the complete static link graph, establish actual wheel build overrides,
or close independent legal/security/replacement/source-access acceptance.

A selected local release-evidence policy may set `supplemental_notices` to a
prepared materials directory. `scripts/release_notices.py` validates and embeds
that material as a hash-indexed snapshot in the core review package. It checks
Python distribution identities against the image SBOMs, exact METADATA license
declarations and all declared `License-File` entries, including attribution files.
CPython's runtime license is preserved separately from the Python package notices.

Rust coverage binds the retained Cargo metadata, actual manifests, collected notices,
builder identity and retained executable/source continuity. Where crate archives omit
dedicated texts, exact archive hashes are checked against Cargo.lock. Notices taken
from another repository file bind the immutable commit recorded in the locked crate
archive. Nonstandard notice paths such as `LICENSES/MIT.txt` and `MIT-LICENSE` remain
covered. Cargo's `license` field is a package grant declaration, while `license-file`
identifies a text file; these are distinct forms of evidence. See the
[Cargo manifest reference](https://doc.rust-lang.org/stable/cargo/reference/manifest.html#the-license-and-license-file-fields).

The retained relay versions `libpcre2-8-0=10.46-1~deb13u2`,
`libssl3t64=3.5.7-1~deb13u2` and `openssl-provider-legacy=3.5.7-1~deb13u2`
can be reviewed with their own original notices and exact Debian source packages.
Their pinned base image must be an exact RootFS layer prefix of the retained relay;
newer installed notices are not substituted for those bytes.

This snapshot preserves unresolved grants and remains explicitly unapproved.
`bech32 0.9.1` contains its complete MIT copyright and permission notice in the
header of `src/lib.rs`, rather than a separate LICENSE file. The snapshot preserves
that exact source file and verifies its bytes against the archive checksum in
Cargo.lock. The same notice appears in the
[recorded upstream source](https://github.com/rust-bitcoin/rust-bech32/blob/d12513f1e3768a7f2a2e1b4d650139eb92a4ae9b/src/lib.rs).
CC0-declared crate archives without
dedicated texts are retained with their exact declarations. Collection does not
close source-authenticity, replacement/relinking or final legal acceptance.

### Public source artifact

In the maintainer source workspace, `scripts/build-public-source-archive.py` applies the
same allowlist, private-content, leak, and link gates as the public-slice builder. It then
adds `A4A-SOURCE.json`, which binds every exported path, Git mode, byte size, and SHA-256
to the exact source commit, and creates a deterministic archive:

```console
python scripts/build-public-source-archive.py
python scripts/build-public-source-archive.py --verify build/public-source
python scripts/build-public-source-archive.py --verify-archive build/a4a-public-source.tar.gz
```

The archive verifier is self-contained and does not extract files. It checks the complete
file and directory sets, provenance snapshot ID, content hashes, executable modes, sorted
members, zero timestamps, numeric ownership, and the absence of traversal, links, or
special files. The archive remains an unapproved local candidate until the owner
separately authorizes publication.

### Portable release-evidence package

After the inventory and corresponding-source bundle are both current, join them with the
exact wheels and locked release inputs into one portable directory and deterministic
archive:

```console
python scripts/build-release-evidence.py
python scripts/build-release-evidence.py --verify build/release-evidence
python scripts/build-release-evidence.py --verify-archive build/release-evidence.tar.gz
```

The builder requires a clean worktree. It includes the verified public-source archive,
its provenance manifest, and checksum alongside the binary and licensing evidence. It
checks that the inventory commit is an ancestor of the evidence commit and permits only
the exact non-runtime paths listed in
`scripts/release-evidence-policy.json` to have changed between them. It independently
rehashes all four wheels, each SBOM and the relay Cargo metadata, invokes the offline
corresponding-source verifier, checks the four immutable Docker image IDs against the
local Docker store, and copies the declared release inputs into the package. The archive
uses sorted members, zero timestamps and numeric ownership; its verifier reads members
without extracting them and rejects traversal, links, special files, unexpected files,
and non-deterministic metadata.

The package records immutable image IDs but does not contain Docker image bytes. Its
archive checksum is an integrity handle, not an identity signature. Consequently this
tool does not prove who built an artifact and does not authorize signing, publication,
or deployment.

`relay/Cargo.lock` records resolved Rust dependency versions, not their license texts.
The release-inventory command supplements the final relay image scan with `cargo
metadata --locked --offline --filter-platform
x86_64-unknown-linux-gnu` from the exact builder, because image scanners may not recover
the graph of a statically linked Rust binary. It fails when a resolved Rust package has
no license expression and reports, without hiding, every image package whose scanner
license is `NOASSERTION`. The artifact-bound registry above must cover every such entry;
the applicable notice, source, and relinking obligations still require release review.
This document is not a blanket claim that all dependencies are permissively licensed or
that an SBOM is legal advice.
