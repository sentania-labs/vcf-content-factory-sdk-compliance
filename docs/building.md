# Building from source

You don't need this repo's CI or the VCF Content Factory checkout to
build the `.pak`: the toolchain is a portable tarball. You need:

- **JDK 11+** (`javac` + `jar` on PATH)
- **python3** with `pyyaml` (`python3 -m pip install pyyaml`)
- **The GitHub CLI** (`gh`): used to download the build toolchain
  below. The factory repo is public, so no `gh auth login` is needed
  for the download (authenticate only if you hit anonymous API rate
  limits). No `gh`? See the `curl` alternative under step 1.
- **The Broadcom adapter SDK jar** (`vrops-adapters-sdk-2.2.jar`).
  This is a Broadcom build artifact with no public redistribution
  channel: it is **never** bundled in the toolchain or this repo.
  Get it from your own VCF Operations appliance:

  ```
  scp root@<appliance>:/usr/lib/vmware-vcops/common-lib/vrops-adapters-sdk-2.2.jar .
  ```

  (Also present at
  `/usr/lib/vmware-vcops/suite-api/WEB-INF/lib/vrops-adapters-sdk.jar`.
  Partners can pull it from the Broadcom TAP / partner SDK portal
  instead.)

Then, from the root of this repo:

```bash
# 1. Fetch the build toolchain (pin a full sdk-buildkit-vX.Y.Z tag for
#    reproducibility, or use the floating major sdk-buildkit-v1)
gh release download sdk-buildkit-v1 \
  --repo sentania-labs/vcf-content-factory \
  --pattern 'sdk-buildkit-*.tgz'
# No gh? The asset is public. Its file name carries the full version
# (for example sdk-buildkit-1.0.10.tgz); look it up on the release page
#   https://github.com/sentania-labs/vcf-content-factory/releases/tag/sdk-buildkit-v1
# and fetch it with curl:
#   curl -sLO https://github.com/sentania-labs/vcf-content-factory/releases/download/sdk-buildkit-v1/<asset-file-name>
tar xzf sdk-buildkit-*.tgz

# 2. Point the kit at your SDK jar and build
export VCFCF_SDK_JAR=/path/to/vrops-adapters-sdk-2.2.jar
python3 -m sdk_buildkit validate-sdk .   # cheap loop: compile-check
python3 -m sdk_buildkit build-sdk .      # emits the .pak
```

**Buildkit version: 1.0.11 or later (since build 93).** Build 93
overrides the framework's `certificateCheckUrls` hook (the Validate
Connection certificate accept dialog), which first ships in
sdk-buildkit 1.0.11. The override is marked `@Override` on purpose: with
sdk-buildkit 1.0.10 or older, `validate-sdk` and `build-sdk` fail to
compile with "method does not override or implement a method from a
supertype" instead of building a pak that never offers the dialog. A
tagged release of build 93 or later therefore needs the floating
`sdk-buildkit-v1` tag (which CI uses) to point at 1.0.11 or later, or a
pinned 1.0.11+ tag. A build inside a VCF Content Factory checkout
compiles the framework from the checkout and is not affected.

**Profile data contract.** The bundled profiles under
`profiles/canonical/` follow [CANONICAL_SCHEMA.md](../CANONICAL_SCHEMA.md),
the column-by-column contract between the normalizer scripts and the
adapter. Read it before regenerating a profile or adding a read method.
Site tuning does not need it: see [overrides.md](overrides.md).

The kit carries everything else it needs (including the
`vcfcf-adapter-base.jar` framework runtime that ends up in the pak's
`lib/`). `validate-sdk` is the fast iteration loop; exhaust it before
building paks.

**Dev builds vs releases.** Anything you build this way is a *dev
build*. The **official** artifact for this repo is the one its own CI
builds and attaches to a GitHub Release when a `v*` tag is pushed:
deterministic, with no developer machine in the path.

**Inside a VCF Content Factory checkout** you can skip the toolchain
download and build with the factory's own CLI:
`python3 -m vcfcf_managementpacks build-sdk content/sdk-adapters/compliance`.

**If you fork this repo**, the CI workflow
(`.github/workflows/build-pak-on-tag.yml`) needs one adjustment
before your own `v*` tags will build (it already runs on GitHub-hosted
`ubuntu-latest`, so no runner change is needed).

**SDK jar sourcing**: the upstream workflow fetches the Broadcom jar
from a private repo via an `SDK_RUNTIME_SSH_KEY` deploy-key secret you
won't have. Replace that step with your own source, for example the
appliance-extracted jar in your own private repo or an Actions
secret/artifact store. Then **also update the `--sdk-jar` argument** on
the `build-sdk` line of the workflow to point at wherever your
replacement step puts the jar. The explicit `--sdk-jar` flag overrides
`VCFCF_SDK_JAR`, so setting the env var alone is not enough: if you
leave `--sdk-jar _sdk_runtime/...` in place the build will look for the
upstream path and fail. Do **not** commit the jar to a public repo (no
redistribution).
