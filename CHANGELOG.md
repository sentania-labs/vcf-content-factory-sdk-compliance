# Changelog

## 0.0.0.60 (2026-09-23)

- fix(adapter): build 60: close the build-59 review (knowledge/context/reviews/compliance-build-59.md: 1 BLOCKING, 1 WARNING, 1 NIT). Numbered by finding:
  1. **B1, PR workflow off the self-hosted pool.** `.github/workflows/tests.yml` now runs on `ubuntu-latest` (public repo, pull_request trigger: fork PR code must never reach the runner that holds the release deploy key). SHA pins and `contents: read` kept; no secrets and no SDK jar in that job. Every suite is SDK-free, so the full set runs there: the generator `--check`, BenchmarkLoaderTest, ProfileSetTest, BenchmarkSelectorTest, ControlEvaluatorTest, ComplianceRollupTest, ComplianceDecisionsTest, MixedVersionSimulationTest, and the generator unittest suite. The tag workflow is unchanged and runs the same set before build-sdk.
  2. **W1, cleanup read is observable.** `ComplianceStitcher.latestCompliant` returns a `LatestRead` (values, requests completed, numeric Compliant values returned, error). The adapter logs one "Stale-control cleanup read" line per cycle (objects queried, requests, values returned, zeros set to -1, objects skipped) and one WARN per failed batch (objects, requests completed, values returned, error). **Acceptance plan (supersedes builds 58 and 59):** (a) ops-recon runs one read-only `GET /api/resources/stats/latest?resourceId=<devel host>&statKey=VCF-CF Compliance|<a live 9.1 control>|Compliant` to confirm the response shape on devel 9.0.2; (b) install, record the fixed-9.1 baseline; (c) set one devel instance to fixed `VMware_SCG_8.0` for one cycle (creates 8.0-only keys, some at 0 with alerts), then back to `Auto (by version)`; confirm the next cycle's cleanup line reports values returned and zeros set to -1, those keys read -1, and their per-control alerts cancel; (d) repeat (a) to (c) on prod 9.1 after its first install.
  3. **N1, request volume.** Stats/latest GETs are packed by URL length (budget 6000 characters; keys chunked at half the budget, then as many resourceIds as fit) instead of fixed 20 ids x 30 keys, and cleanup batches grow from 20 to 500 objects. Measured on the bundled profiles: 5,000 VMs on SCG 9.1 take 41 requests (was 250), 500 hosts 7 (16 in the worst case of all 86 host controls). POST `/api/resources/stats/latest/query` was not used: the framework stitcher exposes GET only, and adding POST is a framework (`src/vcfcf_*`) change. docs/overview.md request sentence corrected.
  - Tests: ComplianceDecisionsTest asserts every generated path fits the URL budget and covers every (resource, control) pair exactly once, for 5,000 VMs x 1 key and 300 hosts x 86 keys. All suites pass.

## 0.0.0.59 (2026-09-23)

- fix(adapter): build 59: close the build-58 review (knowledge/context/reviews/compliance-build-58.md: APPROVED with 1 WARNING + 4 NIT; all fixed before the PR). Numbered by finding:
  1. **W1, cleanup from live values, no key creation.** The union / first-sight / daily re-sweep cleanup is gone. At the end of every cycle the adapter bulk-reads, per 20 pushed objects, the latest `VCF-CF Compliance|<control_id>|Compliant` values of the controls outside each object's current benchmark (`GET /api/resources/stats/latest` with repeated `resourceId` / `statKey`, chunked at 20 ids x 30 keys, through the stitcher's existing ambient `get`), and pushes -1 (with an explanatory Actual) only where the latest value is 0. No key is created, keys at -1 or 1 are untouched, and cleanup heals every cycle. A failed read skips that batch for the cycle (logged, counted) with no fallback. New SDK-free `ComplianceDecisions.candidateControlIds`, `staleZeroControls`, `latestCompliantPaths`, `controlIdOfCompliantKey`; new `ComplianceStitcher.latestCompliant` (only numeric data points are used, a missing value is never read as 0). The endpoint shape is taken from the vendor operations API spec (reference/docs/operations-api-9.1.json); first live use is devel acceptance. docs/overview.md rewritten to match; the "harmless -1 keys" text is gone.
  2. **N1, docs vs code.** docs/overview.md and the README key list state that `unreadable_count` is not pushed when the governing version cannot be read.
  3. **N2, sweep timing.** Moot: the 24-cycle sweep is removed and no count- or time-based logic remains.
  4. **N3, benchmark memory separate.** `AppliedBenchmarkTracker` replaced by `LastBenchmarkMemory`: last cycle's benchmark per object for the B2 fallback only, emptied only by a collector restart or an instance edit (and trimmed to objects still in inventory). It holds no cleanup state.
  5. **N4, CI on push and PR.** New `.github/workflows/tests.yml` runs `generate_compliance_alerts.py --check` and `ci/run_java_tests.sh` on every push and pull request (same self-hosted runner and SHA-pinned actions as the tag workflow; read-only permissions; per-ref concurrency).
  - **Acceptance plan update (supersedes build 58's step b "first-sight cleanup"):** after switching one devel instance to Auto, expect NO new `Compliant` = -1 keys (devel's v3 keys hold no stale 0s outside 9.1). Verify the live read works: no "Stale-control cleanup skipped" WARN in the adapter log, and the completion line reports "0 stale per-control key(s)". To see a flip live, a host must have a control reading 0 that its new benchmark does not evaluate.
  - Tests: ComplianceDecisionsTest covers a stale 0 outside the benchmark flipping to -1, a 0 inside it untouched, -1 / 1 untouched, a failed read cleaning nothing, no key creation, and the chunked query paths. MixedVersionSimulationTest runs three cycles against a simulated VCF Ops value store (first cycle creates nothing; after the 8.0 to 9.0 upgrade exactly the stale 0s outside 9.0 flip to -1 while the in-benchmark failure stays 0; a failed read changes nothing and creates no keys).

## 0.0.0.58 (2026-09-23)

- fix(adapter): build 58: close the build-57 review (knowledge/context/reviews/compliance-build-57.md: 3 BLOCKING, 6 WARNING, 4 NIT; N3 was a design-doc fix made by the orchestrator). Numbered by finding:
  1. **B1, vCenter stitch identity.** `ComplianceStitcher.matchVCenterAdapterInstance` now delegates to the SDK-free `ComplianceDecisions.matchVCenter`: a known vCenter instance UUID resolves only through `VMEntityVCID` (not indexed means no push, logged); an unreadable UUID falls back to an exact, case-insensitive `VCURL` match only. The prefix, display-name and single-vCenter (`singletonOfKind`, removed) fallbacks are gone, so one instance's rollup can no longer land on another vCenter's object.
  2. **B2, version unreadable is not "no benchmark".** `BenchmarkSelector.Selection` separates `versionUnreadable()` from `noBenchmark()` (a readable, unmapped version only). `ComplianceDecisions.decide` scores an object whose version cannot be read against the benchmark it had last cycle; with none, the object is unreadable: `profile_name` "benchmark unknown: <product> version unreadable", `non_compliant` = 1, `no_benchmark` = 0, not scored, no alert cleanup, not recorded, counted in the new rollup bucket `Rollup|Benchmark|unknown|objects`, and a host keeps its last-known score in the host average.
  3. **B3, retired-key dashboard unbundled.** `dashboards/compliance-overview.yaml` (Compliance Fleet Overview, reads the ComplianceWorld Summary metrics retired in build 57) removed from `bundled_content`; the file stays for the content round. `views/compliance-host-overview.yaml` stays bundled: it reads only score / pass_count / fail_count / total_count / profile_name, all still pushed.
  4. **W1, self-healing alert cleanup.** New SDK-free `AppliedBenchmarkTracker`. Cleanup runs on a benchmark change (against the previous profile) and on an object's first sight since the tracker was cleared (against the union of every bundled profile's controls for the kind). The tracker is empty at collector start, cleared on an instance edit (configure), and cleared every 24 cycles (daily re-sweep, so a silently failed push self-heals). An object is recorded only after a push was attempted.
  5. **W2, no stale counters.** The no-benchmark push zeroes `total_count` / `pass_count` / `fail_count` / `unreadable_count` (keeps `no_benchmark` = 1); the nothing-evaluated push zeroes them too; an evaluated object with nothing scored pushes `pass_count` / `fail_count` as 0. `score` and `avg_score` stay omitted when nothing is scored (no stand-in score); `Rollup|<K>|scored` is pushed every cycle so a retained average is identifiable (owner-accepted). docs/overview.md sentence corrected.
  6. **W3, CI gates.** `.github/workflows/build-pak-on-tag.yml` runs `python3 scripts/generate_compliance_alerts.py --check` and `bash ci/run_java_tests.sh` after the JDK step and before build-sdk (same runner, no new actions).
  7. **W4, decisions extracted.** New SDK-free `ComplianceDecisions` (benchmark decision, VM follows host, every per-object payload, orphan set, vCenter match) used by the adapter; new `ComplianceDecisionsTest`; `MixedVersionSimulationTest` now drives those functions and the tracker over two cycles (8.0 host upgraded to 9.0 cleans exactly the 8.0-only controls; a 7.0 host with a failed version read reuses 7.0 with no cleanup; a new host with an unreadable version is non-compliant, not no-benchmark).
  8. **W5, docs pointer.** docs/overview.md opens with "Stitched onto VMWARE resources": the per-object keys, the rollup and the 144 alerts. docs/README.md and docs/inventory-tree.md are regenerated by the factory's docs_gen on every build, so the pointer there needs a generator hook (TOOLSET GAP, reported).
  9. **W6, devel baseline.** The stale "devel runs 9.0" line in UNAUDITED_CONTROLS.md corrected: devel instances are stored fixed `VMware_SCG_9.1`, hosts on ESXi 9.1.1. README upgrade example now uses 9.1. **Acceptance plan:** (a) after install, record the fixed-9.1 baseline on devel (expect VM scores to rise from the vmx minimum comparison and host totals to shrink from the five demoted 9.1 prose controls); (b) edit ONE instance to `Auto (by version)` and verify live: selection (profile_name per object), first-sight cleanup (`Compliant` = -1 on controls outside SCG 9.1), per-control alert cancellation, and the rollup on that instance's vCenter object.
  10. **N1.** VM enumeration reads `name` and `runtime.host` in the one container-view RetrieveProperties (was an extra `runtime.host` round trip per VM); the per-VM read remains only as a fallback when the bulk read returns nothing.
  11. **N2.** `normalize_scg_v67.py` docstring lists the full prerequisite set (scg_7.0.csv and scg_9.1.csv in the output directory).
  12. **N4.** The vDS / portgroup / cluster path gates on vim_property + esxcli, matching `BenchmarkSelector.evaluatedFor` and the alert generator.
  - Compliant = -1 for unreadable controls kept as built (owner-approved).
  - Tests: 7 Java suites + generator unittest suite, all passing.

## 0.0.0.57 (2026-09-23)

- feat(adapter): build 57: version-aware SCG selection, profile-free keys, per-vCenter rollups, per-control compliance alerts (design: knowledge/designs/sdk-adapters/compliance-v3-version-aware.md). **Breaking key change, no migration (owner-approved).** Numbered:
  1. **Auto (by version), new default.** `benchmark_profile` gains `Auto (by version)` (default for new instances) plus fixed `VMware_SCG_6.7` and `VMware_SCG_7.0`. Auto scores hosts by their ESXi version, VMs by their host's ESXi version, and vCenter / cluster / vDS / portgroup by the vCenter version (a vDS's own version is not used); `major.minor` picks SCG 6.7 / 7.0 / 8.0 / 9.0 / 9.1. An unmapped or unreadable version gets `profile_name` "no benchmark for <ESXi|vCenter> X.Y" (or "(version unreadable)"), `no_benchmark` = 1, no score, no per-control results. All five profiles load once per conf dir. A fixed choice forces one profile for every object (pre-v3 behavior). Existing instances keep their stored value (instance config survives pak upgrade); a blank stored value keeps the pre-v3 SCG 8.0 fallback.
  2. **Profile-free per-control keys.** `VCF-CF Compliance|<control_id>|{Actual,Expected,Description}` (properties) and `...|Compliant` (metric: 1 compliant, 0 non-compliant, -1 not evaluated). Unreadable controls now push -1, not 0, so the per-control alert never fires a runbook for a setting the adapter could not read. New per-object metrics `VCF-CF Compliance|non_compliant` (fail_count > 0 or unreadable_count > 0) and `VCF-CF Compliance|no_benchmark`; score / pass_count / fail_count / total_count / unreadable_count / profile_name unchanged.
  3. **detectProfileChange replaced by per-object benchmark tracking.** On an object's benchmark change, controls the old SCG evaluated and the new one does not get `Compliant` = -1 and an explanatory Actual, so their alerts cancel. The old method's kind names ("VMwareAdapter Instance", "VmwareDistributedVirtualSwitch") actually matched the stitcher's; its real defect was omitting ClusterComputeResource from the count. The count is gone with the rewrite.
  4. **Per-vCenter rollup on each VMWARE `VMwareAdapter Instance`:** `VCF-CF Compliance|Rollup|<K>|{scored,non_compliant,no_benchmark,score_sum,avg_score}` for All, Host, VM, vCenter, Cluster, vDS, Portgroup; `Rollup|Benchmark|<B>|objects` for SCG_6.7..SCG_9.1 and none (plus Custom when used); `Rollup|Host|scored_stale` keeps the build-49 last-known-score rule visible. avg_score only when scored > 0.
  5. **ComplianceWorld Summary numbers retired.** The world is one resource shared by every instance (last-writer-wins). It now pushes only `Summary|last_scan_timestamp`; the numeric Summary attributes and `Summary|profile_name` are removed from describe.xml.
  6. **Per-control compliance alerts, generated.** `scripts/generate_compliance_alerts.py` (stdlib, deterministic, `--check` gate) writes 144 symptoms, 144 alert definitions and 144 recommendations into marked blocks of describe.xml / resources.properties from the union of scored controls across the five profiles. Symptom: metric `VCF-CF Compliance|<control_id>|Compliant = 0` on the VMWARE kind. Alert: type 15 subType 21 (COMPLIANCE), impact badge risk, name "<control_id>: <title>", severity from SCG priority (P0 Critical, P1 Immediate, P2 Warning). Recommendation: remediation_text from the newest profile scoring the control, labelled with its source SCG and noting when other versions word the fix differently.
  7. **Score alert subtype.** `vcfcf_compliance_score_degraded` subType 20 (CAPACITY) -> 21 (COMPLIANCE).
  8. **Prose expected values unscored.** New `profiles/manual_review.csv` (22 rows, per profile, bundled profiles only) demotes controls whose SCG expected value is prose to manual_audit. `vm.virtual-hardware` gets a real minimum comparison instead: `vmx-N or higher|newer` passes iff the VM's vmx-M has M >= N (SCG 9.1, and 7.0 where the row is now scored); bare `vmx-N` (8.0 / 9.0) keeps exact equality. 7.0 `esx.etc-issue` key case fixed (`Config.Etc.Issue` -> `Config.Etc.issue`) in the 7.0 driver. 7.0 and 9.1 canonical CSVs regenerated (4 rows changed).
  9. **Cardinal-rule fixes found on the way.** A failed VM extraConfig read used to fall back to an empty map, passing every "X or Undefined" control; it is now UNREADABLE. Failed vim-property reads (host, VM, vDS, portgroup, cluster), a failed cluster vSAN probe, and a failed vCenter settings read now fold to UNREADABLE instead of a silent skip or profile-name-only push.
  10. README, adapter.yaml description, docs/overview.md, docs/installing.md, REFERENCE.md, CANONICAL_SCHEMA.md and UNAUDITED_CONTROLS.md updated to v3 (no longer "hosts only").
  - Tests: `ci/run_java_tests.sh` now runs BenchmarkLoaderTest, ProfileSetTest, BenchmarkSelectorTest, ControlEvaluatorTest, ComplianceRollupTest, MixedVersionSimulationTest (simulated ESXi 6.7 / 7.0 / 8.0 U3 / 9.0 / 9.1 / 10.0 hosts, VMs following hosts, vDS and portgroup following vCenter, rollup arithmetic with no_benchmark and unreadable) and the generator's unittest suite. All passing.

## 0.0.0.56 (2026-08-25)

- fix(adapter): build 56 — close the SCG-benchmark-set review (knowledge/context/reviews/compliance-scg-benchmark-set-2026-08-25.md: 1 BLOCKING + 3 WARNING + 2 NIT). Numbered:
  1. **BLOCKING (B1) — unknown profile names now fail loud.** `BenchmarkLoader.resolveBundledProfileName` no longer silently falls back to VMware_SCG_8.0 for an unknown NON-null `benchmark_profile`: it throws with an actionable message ("configured benchmark_profile 'X' is not bundled in this version; choose VMware_SCG_8.0 / VMware_SCG_9.0 / VMware_SCG_9.1 or Custom"), which propagates out of the collect cycle so the instance goes to a visible failed state instead of confidently scoring against a benchmark the operator did not configure. Null/blank keeps the describe.xml default; `Custom` without a `custom_profile_path` gets its own actionable message. **MIGRATION (CIS users):** after upgrading to this build, any adapter instance still configured `CIS_vSphere_8` stops collecting and shows the message above — edit the instance and select one of the three SCG profiles (or Custom + path). This is deliberate: the previous silent SCG-8.0 fallback would have reported a wrong-benchmark score indefinitely with no on-dashboard trace.
  2. **WARNING (W1) — `network-reset-port` evaluability restored in 9.1.** Upstream's 9.1 Setting-Location text change migrated the control's canonical id from `vds.network-reset-port` to `dvpg.network-reset-port`, dodging the id-keyed reclass map, so the 9.1 row silently shipped `powercli_only`. The 9.1 driver now adds the DVPG-keyed reclass (`bool:config.policy.portConfigResetAtDisconnect`, expected `true`); DVPG is the more correct target kind anyway (`config.policy.portConfigResetAtDisconnect` is a DVPortgroupConfigInfo.policy field). The build-55 "no control lost evaluability" claim was false under id migration; UNAUDITED_CONTROLS.md no longer asserts perfect id stability.
  3. **WARNING (W2) — dead `advanced_setting` rows demoted.** 9.1's assessment-text changes had promoted `vc.smtp` (comma-joined multi-key parameter) and `vc.snmp` (literal `<x>` placeholder) to `advanced_setting`; neither is a resolvable OptionManager key, so both were permanent absent-key skips inflating the evaluable count. The driver now demotes advanced_setting rows whose parameter is comma-joined or contains a `<...>` placeholder to `manual_audit`, mirroring the factory's newline-multi-key rule. **Honest 9.1 evaluable count: 100 of 260** (59 advanced_setting + 31 vim_property + 5 of 9 esxcli + 5 vami_api, counting only recipe-backed rows; was claimed 101 in build 55) vs 98 of 226 in 9.0.
  4. **WARNING (W3) — normalizer driver patches guarded.** Every in-process patch in `scripts/normalize_scg_v91.py` (SOURCE_TOKEN, header constants, COMPONENT_MAP / SOURCE_ID_PREFIX_MAP / _VIM_RECLASS_BY_CONTROL_ID, classify_parameter_kind) is now preceded by a hasattr check that SystemExits naming the moved target — a factory rename fails the regeneration loudly instead of emitting plausible wrong output. Canonical regeneration verified byte-reproducible.
  5. **NIT (N1)** — the UNAUDITED_CONTROLS.md 9.1 reconciliation-pending note is date-stamped (2026-08-25, build 56) so it cannot silently become permanent.
  - New executing test: `tests/com/vcfcf/adapters/compliance/BenchmarkLoaderTest.java` + `ci/run_java_tests.sh` (plain-main, JDK-only) asserts the resolve/throw/filename contract, including the CIS_vSphere_8 loud-fail. Passing as of this build.


## 0.0.0.55 (2026-08-25)

- feat(adapter): build 55 — SCG-only benchmark set. Adds **VMware_SCG_9.1** (source: vmware/vcf-security-and-compliance-guidelines cloud-foundation/9.1 controls CSV, VERSION 910-20260612-01; 260/260 source rows normalized, 101 evaluable vs 98 in 9.0, zero controls lost evaluability vs 9.0) via a new adapter-repo normalizer driver `scripts/normalize_scg_v91.py` (thin delta over the factory's 9.x pipeline: no-newline headers, new NIST 800-53R5 column ignored by name-lookup, `SCG-9.1` source token, new informational-only sub-products `automation`/`pnr`/`networks`). **Removes CIS_vSphere_8** (profiles, canonical CSV, describe.xml enum, loader case, doc mentions) — owner's verbatim scope decision: "okay for now: we are only going to ship SCG 8.0 SCG 9.0 and SCG 9.1". An existing instance still configured `CIS_vSphere_8` falls into the loader's existing unknown-name fallback (VMware_SCG_8.0); the pushed `profile_name` property shows the resolved profile. Scoring, identity/stitching, and the unreadable-is-not-compliant rules are unchanged.

## 0.0.0.54 (2026-06-25)

- fix(framework): build 54 — dev preview build under the **corrected** hand-build version convention. The previous build (53) used `major.minor.patch = 99.0.0` to make hand-builds visually distinct, but `99.x` is a defect: a `99.0.0.x` pak makes a future real `1.0.0.x` CI release look like a **downgrade**, triggering upgrade-refusal on the target. Corrected convention: dev/hand builds set `major.minor.patch = 0.0.0` (always strictly below any real release), so this pak's version is `0.0.0.54`; the `build_number` counter continues incrementing normally (53 → 54). CI/release builds keep the `1.0.0.x` line. No adapter source change vs build 53 — compliance's own describe.xml, resources.properties, Java source, content, and scoring are byte-unchanged; the only delta vs build 53 is the version string. Bundles the localization-fixed framework base jar (`vcfcf-adapter-base.jar`, sha256 `4eabad523a30ed547b5aa8987b26d1517dc9d7c89c87a6217ac642ebb3734c53`; carries the `AdapterDescribe.make(InputStream)` → `make(String)` swap so describe.xml `nameKey`s resolve to localized strings). Not for release — the official `1.0.0.x` line is cut by the pak repo's CI on a `v*` tag.

## 99.0.0.53 (2026-06-25)

- fix(framework): build 53 — dev preview build. Hand-built local preview that rebundles the freshly-rebuilt, localization-fixed framework base jar (`vcfops_managementpacks/adapter_runtime/vcfcf-adapter-base.jar`, 60252-byte, Jun 24 18:28; carries the `AdapterDescribe.make(InputStream)` → `make(String)` swap so describe.xml `nameKey`s resolve to localized strings instead of raw key numbers — framework-reviewer APPROVED, `context/reviews/framework/onDescribe-localization-fix.md`). **Versioning marker:** this is the first pak under the new hand-built dev-preview convention — `major.minor.patch` is set to `99.0.0` so locally hand-built paks are visually distinct from CI/release builds (which stay on the `1.0.0.x` line); the `build_number` counter continues incrementing normally (52 → 53). No adapter source change vs build 52 — compliance's own describe.xml, resources.properties, Java source, content, and scoring are byte-unchanged; the only delta inside the pak vs the prior rebuild is the version string and the (identical-content) base jar. Not for release — the official `1.0.0.x` release line is cut by the pak repo's CI on a `v*` tag.

## 1.0.0.52 (2026-06-25)

- fix(framework): build 52 — rebuild-only adoption of the framework `onDescribe()` localization fix. No adapter source change. The framework base swapped `AdapterDescribe.make(InputStream)` → `make(String)` in `vcfops_managementpacks/adapter_framework/src/com/vcfcf/adapter/VcfCfAdapter.java` so the SDK auto-loads `<conf>/resources/resources.properties` and the describe.xml `nameKey`s resolve to their localized strings instead of rendering as raw key numbers in the VCF Ops UI (framework-reviewer APPROVED, 0 BLOCKING; `context/reviews/framework/onDescribe-localization-fix.md`). Every SDK pak bundles `vcfcf-adapter-base.jar`, so the previously-built compliance pak (build 51) is stale and ships the pre-fix jar. This build rebundles the rebuilt base jar (60252-byte, Jun 24 18:28) carrying the fix. Compliance's own describe.xml, resources.properties, source, content, and scoring are byte-unchanged — the only delta inside the pak is `lib/vcfcf-adapter-base.jar`. Localization bundle verified intact in the built pak (resources.properties present in both bundle copies, all describe.xml nameKeys mapped, no orphans). validate-sdk clean; pak-compare vs build 51 reported in the build result (jar byte-delta inside an otherwise-unchanged path).

## 1.0.0.51 (2026-06-10)

- fix(adapter): build 51 — close the cross-vCenter MOID-trap defect surfaced by sdk-adapter-reviewer in the vcommunity build-1 review (`context/reviews/vcommunity-build-1.md`, MOID-trap WARNING), which confirmed the same defect exists in compliance's stitcher. Foreign vim25-backed VMWARE resources (HostSystem, VirtualMachine, VmwareDistributedVirtualSwitch, DistributedVirtualPortgroup, ClusterComputeResource) were resolved by bare MOID/name with no vCenter scoping. A MOID (`host-10`, `vm-42`) is only unique per vCenter, so in a multi-vCenter VCF Ops the `/api/resources` load returns every vCenter's `host-10` and the by-moid index keeps only the last writer — a push could land on the wrong vCenter's resource. **Live exposure:** the devel instance runs TWO compliance instances (mgmt + wld01). Port of the vcommunity build-2 fix pattern, adapted to compliance's stitcher (which carries the extra `VMwareAdapter Instance` kind — left intentionally unscoped, as it already keys on `VMEntityVCID` and represents the vCenter instances themselves, not foreign vim25 resources):
  1. `ComplianceStitcher.setOwningVcUuid()` pins the vCenter Instance UUID this adapter instance monitors. `ComplianceAdapter.loadStitcherResources()` resolves it from `vsphere.getVCenterInstanceUuid()` and pins it once per cycle BEFORE the `load*` calls; a UUID-read failure degrades to unscoped (single-vCenter safe) and logs a WARN rather than aborting the cycle.
  2. The generic vim25 loader (`loadResourcesForKind`) now reads each row's `VMEntityVCID` and skips any resource whose VCID does not match the owning UUID — so a bare MOID can only resolve to a resource belonging to the monitored vCenter. Degrades to unscoped resolution when the owning UUID is unknown OR a row carries no `VMEntityVCID` (never drops a resource it cannot disambiguate); the load log states whether scoping engaged and how many foreign-vCenter resources were skipped.
  Single-vCenter deployments are unaffected (no foreign-vCenter rows to skip). No scoring change, no describe.xml/topology change (pure stitcher resolution logic). validate-sdk clean; pak-compare reported in the build result.
- fix(content): dashboard YAML now self-describes coords + hidden after factory 00d3382 reverted the two compliance-specific renderer compensations (the global `hidden:true` default and the `_gridster_coords` +1 shift, both introduced in build 26). `dashboards/compliance-overview.yaml` now carries `hidden: true` at the dashboard level explicitly, and every widget's `coords.x`/`coords.y` are bumped +1 to 1-based (gridster convention) so the renderer's new pass-through matches the previously deployed output. Rendered-output equivalence verified: rendering the edited YAML through the current (post-00d3382) renderer is byte-identical to rendering the old YAML through the pre-00d3382 renderer — `hidden:true`, top-left widget at (x:1,y:1), all eight widgets unchanged. (Carried in from Unreleased; no further source change.)

## 1.0.0.50 (2026-06-10)

- fix(adapter): build 50 — close the build-49 review (context/reviews/compliance-build-49.md: 1 BLOCKING + 2 WARNING + 1 NIT). All four findings fixed; healthy-host *scoring* unchanged (only the SSL default, a new world metric, a null-guard, and cache eviction). Numbered:
  1. **BLOCKING (B1) — the SSL default now genuinely flips to strict.** Build 49 documented "platform trust by default, allowInsecure=true as the opt-out" but shipped the inverse: `describe.xml` carried `allowInsecure default="true"` and `ComplianceConfig` parsed `!"false".equalsIgnoreCase(...)`, so null/blank/absent (every existing and freshly-created instance) → `allowInsecure=true` → trust-all. Fixed both layers: `describe.xml` `allowInsecure` now `default="false"`, and the parse is `this.allowInsecure = "true".equalsIgnoreCase(allowInsecure)` — only the explicit literal `"true"` opts into trust-all; null / blank / absent / any other value → `false` → validate against the platform trust store. The secure default now actually engages. The configure-time WARN when `allowInsecure=true` is retained, and `sslSocketFactoryFor`'s "platform trust by default / allowInsecure opt-out" docstring is now accurate (no longer contradicted by the config layer). **Upgrade impact (now real, per the build-49 deployment note):** any instance pointed at a vCenter whose certificate is not in the platform trust store must either import the cert or explicitly set `allowInsecure=true`, or vCenter SOAP collection fails TLS validation. The failure is loud and actionable (the `sslSocketFactoryFor` WARN names the remedy); the install runbook must call this out.
  2. **WARNING (W1) — first-class world-level staleness visibility.** Added `Summary|hosts_scored_stale` (describe.xml ResourceAttribute, nameKey 28; resources.properties "Hosts Scored From Stale Cache"), pushed on the ComplianceWorld resource EVERY cycle. It is the count of hosts whose contribution to `avg_host_score` came from `lastKnownHostScore` this cycle (channel-unreadable but folding a last-known score); 0 when every averaged host was read live. A new `HostStats.staleScored` counter is incremented in `applyLastKnownForUnreadableHost` (the only stale-fold site) and emitted unconditionally, so an operator can now see "N of M averaged hosts are stale" directly instead of inferring it from the indirect `total_unreadable_controls` count. Never-read hosts remain excluded entirely (unchanged); `staleScored` is a subset of `scored`.
  3. **WARNING (W2) — null-guarded the last-known-score cache write.** `lastKnownHostScore.put(hostId, cr.score)` is now wrapped in `if (hostId != null)`, matching the read side (`applyLastKnownForUnreadableHost` already guarded `hostId == null`). `ConcurrentHashMap.put` NPEs on a null key, and the per-host loop has no per-host try/catch (`collectHosts throws Exception`), so a host with a null MOID would have aborted the whole cycle. Likelihood was low (HostInfo is only built with a non-null `ref.value` and only when `name != null`), but the asymmetry build 49 introduced is removed.
  4. **NIT (N1) — bounded the cache across host churn.** New `evictAbsentHostScores(hosts)` runs at the end of `collectHosts` and `retainAll`s `lastKnownHostScore` against the current `getHosts()` MOID set, so a host removed from vCenter no longer lingers in the map forever. A host that is merely unreadable this cycle is still enumerated by `getHosts()` (it stays in `hosts`), so its cached score survives — only genuinely de-inventoried hosts are evicted. Logs an INFO when any key is evicted.
- **Bundled framework jar refreshed** to the fixed `vcfcf-adapter-base.jar` built from factory `main` d59785a, which carries the framework fixes: `RelationshipBuilder.resource()` + `ForeignResourceResolver.fetchAndCache()` `ResourceKey` arg-order correction (`(name, kind, adapterKind)` — relationship edges were silently dropped at persistence), the `SessionCookieAuth` single-retry-on-401/403 for session strategies, and the removal of the JDK-restricted Host header in `sendWithRoundRobin`. **Compliance exercises none of these paths directly** — it builds its own `ResourceKey` for the synthetic world (not via `RelationshipBuilder`), stitches via `SuiteApiStitcher.pushProperties`/`pushStats` (no `RelationshipBuilder` edges), and uses ambient `SessionCookieAuth` against localhost Suite API (the 401-retry/Host-header paths are not on its hot path). The jar refresh is for **consistency** — every adapter built this round bundles the same current framework — not because compliance depends on any of these fixes. The bundled jar was rebuilt from current `adapter_framework` source (stale `adapter_runtime/vcfcf-adapter-base.jar` deleted first so `_ensure_framework_jar` regenerates), and the built pak's `lib/vcfcf-adapter-base.jar` was verified to contain the corrected `RelationshipBuilder` (see build report).
- validate-sdk clean; pak-compare vs build 49 reported in the build result (describe.xml diff expected for the `allowInsecure default` flip + the new `hosts_scored_stale` attribute).

## 1.0.0.49 (2026-06-10)

- feat(adapter): build 49 — four changes (Scott-approved scope). Rebuilt against the freshly-rebuilt framework jar that adds the opt-in collect-path discovery contract (context/framework_v2_migration.md §22). Numbered:
  1. **Task #19 — collect-path discovery adoption.** VCF Ops 9.0.2 never invokes `onDiscover()` for adapter3-path collectors, so a FRESH instance heartbeats GREEN but discovers zero resources forever (compliance only has resources on devel/prod because they pre-date the migration). Adopted the §22 framework recipe: added `@Override protected boolean discoverOnCollect() { return true; }`, moved the single-synthetic-`ComplianceWorld` enumeration from `getDiscoverer()` into `@Override protected void enumerateResources(ResourceSink sink)` (framework `com.vcfcf.adapter.spi.ResourceSink`; `dr.addResource` → `sink.accept`), and DELETED `getDiscoverer()` (the framework default `onDiscover()` now drives the same `enumerateResources` body). The framework calls `enumerateResources(this::registerNewResource)` at the top of every collect cycle. **Resource-key stability:** the enumerated key is a CONSTANT — kind `ComplianceWorld`, adapterKind `vcfcf_compliance`, one identifier (`world_id`=`compliance_world`, isUnique=true) — built by the SAME unchanged `worldResourceConfig()` the deleted discoverer used; no host/inventory input, so it cannot drift between cycles, and `registerNewResource` is idempotent on the identifying-identifier set, so re-enumerating every cycle re-registers the already-known world rather than duplicating it. `enumerateResources` throws on failure (never silently enumerates nothing — §22 failure posture).
  2. **Task #12 — vSphere SOAP socket trust.** `VSphereClient`'s raw-SOAP HTTPS connection no longer hard-codes a trust-all `SSLSocketFactory`. New `ComplianceAdapter.sslSocketFactoryFor(config)` picks the factory in line with the framework SSL convention: **platform trust by default** via `getPlatformSslContext()` (the same context `HttpClientBuilder.platformSsl(this)` installs), with **`allowInsecure` as the documented per-adapter-config opt-out** → `insecureSslContext()` (trust-all). The chosen factory is injected into `VSphereClient` (new SSLSocketFactory + `trustAll` constructor params) and threaded into the per-cycle `EsxcliSoapClient`, so the esxcli slice honours the same trust decision. Hostname verification is bypassed ONLY on the `allowInsecure` path; the platform-trust path keeps the JDK default verifier. `allowInsecure=true` is surfaced as a WARN at configure time. The legacy no-arg `VSphereClient` constructor keeps the trust-all factory for standalone/test use.
  3. **Removed the shadow `adapterLogger()`** (migration guide §15 — never shadow). Deleted the local `adapterLogger()` helper and routed all three helper-client loggers through the framework `componentLogger(Class)`: `VSphereClient`, `SuiteApiStitcher`, `ComplianceStitcher`. `setLevel` is now handled by the framework; the build-46 dead-logger footgun is eliminated by construction.
  4. **Task #16 — world `avg_host_score` uses last-known scores (Scott: "use last instead of current").** Added an in-memory `ConcurrentHashMap<String,Double> lastKnownHostScore` keyed by stable host MOID. A successfully-scored host records its score; when a host is channel-unreadable this cycle, its last-known score (if any) is folded into the world `avg_host_score` so the denominator stays full and an unreadable host no longer silently shrinks the denominator and flatters the average. Hosts with NO last-known score (never read since process start) stay excluded — we never invent an unobserved score. **Collector-restart caveat:** the cache is in-memory only and resets on restart, so the first cycle(s) after a restart average readable-only (build-48 semantics) until the cache re-warms. Per-host wire behavior is UNCHANGED (build-48: no `score` stat pushed when `totalCount==0`); only the world rollup input changes.
  - Also: updated the `pushComplianceViaClient` docstring (build-48 review NIT, context/reviews/compliance-build-48.md) — the "byte-identical to v1" claim is now scoped to `totalCount>0` and documents the build-48 `totalCount==0` score-omission gate as an intentional deviation. validate-sdk clean; pak-compare vs build 48 reported in the build result.

## 1.0.0.48 (2026-06-10)

- fix(adapter): build 48 — close the build-47 per-resource sentinel-score leak (reviewer CHANGES REQUESTED, context/reviews/compliance-build-47.md: 1 BLOCKING + 1 WARNING). Build 47 fixed the denominator collapse but traded it for a downstream leak: an unreadable host's `totalCount==0` ComplianceResult carries `cr.score == 100.0` (the zero-divisor sentinel from `evaluateControlsUnreadable`), and `pushComplianceViaClient` published it unconditionally as `VCF-CF Compliance|score = 100` — so the per-host symptoms (`host_compliance_score_warning.yaml`/`_critical.yaml`, LT 95 / LT 80) saw green 100, fired nothing, and a blind host masqueraded as perfect. Two changes, both on the known-unreadable path only — healthy-host evaluation byte-identical (pak-compare vs 47: 0/0/0). Numbered:
  1. **BLOCKING — no-sentinel per-resource push.** `pushComplianceViaClient` now guards on `cr.totalCount > 0` before emitting `score`/`pass_count`/`fail_count`: a `totalCount==0` result OMITS those three stats entirely and pushes only `total_count=0` + `unreadable_count`, mirroring the world rollup's own `scored>0` discipline (ComplianceAdapter.java:330). The per-host symptoms now see "no data" instead of a sentinel 100. Not `score=0` (would false-trip CRITICAL); absent is the only honest per-resource value for a host nothing could be scored on. Per-control `|Compliant`/`|Actual`/`|Expected`/`|Description` (all already honestly `(unreadable)`) still push.
  2. **WARNING — unified unreadable path.** The `AdvancedSettingsUnreadableException` (flap-between-reads) branch no longer folds only the advanced_setting channel while scoring vim/esxcli live from cache. It now treats the WHOLE host as unreadable — folds advanced_setting (`evaluateControlsUnreadable`) + vim/esxcli (`unreadableVimResult`), emits one loud WARN, pushes the no-score result, and `continue`s — identical to the connection-state branch. A half-connected host whose OptionManager just vanished is the same disconnected host; its cached vim reads are equally suspect and never produce a partial score. (The generic-exception adv-settings catch — SOAP/transport — is a distinct signal and out of the narrowed brief scope; unchanged.)
- NIT addressed: the 1.0.0.47 entry below reformatted from one wall-of-text paragraph into a numbered list. validate-sdk clean; pak-compare vs build 47: 0 BLOCKING / 0 WARNING / 0 INFO.

## 1.0.0.47 (2026-06-10)

- fix(adapter): build 47 — the honesty build. Closes the build-46 esx04 host-scoped partial-collection regression (root cause: context/investigations/compliance_esx04_partial_collection_2026_06_10.md; predicted by reviewer build-43 WARNING, ControlEvaluator.java:139-150) where a flapping/disconnected host yielded a flattering partial score (83.33 from 6 controls vs baseline 66.67 from 42) because the advanced_setting channel vanished silently from the denominator. Four changes, all on the known-unreadable path only — healthy-host evaluation is byte-identical (pak-compare vs 46: 0/0/0; no describe/content/scoring change for connected hosts). Numbered:
  1. `VSphereClient.getAdvancedSettings()` now THROWS the new typed `AdvancedSettingsUnreadableException` when the `configManager.advancedOption` OptionManager MoRef is null (the disconnected-host signature) instead of returning a silent empty map — distinguishing known-unreadable from known-empty. A host with a live OptionManager and zero options still returns an empty map normally (the legitimate "X or Undefined" allowsUndefined semantics are untouched).
  2. `ControlEvaluator.evaluateControlsUnreadable()` folds EVERY advanced_setting control to UNREADABLE (counted in unreadable_count, excluded from the score numerator/denominator) when the channel is known-unreadable — never silently skipped; total attempted = scored + unreadable, always.
  3. Connection-state guard in `collectHosts`: reads `runtime.connectionState` via the new `getHostConnectionState()`; on disconnected/notResponding, marks ALL of that host's controls (advanced_setting + vim_property + esxcli) UNREADABLE with one loud WARN naming host + state, rather than scoring any partial subset. A half-connected host never produces a score.
  4. Instrumentation: WARNs routed through the FRAMEWORK BASE `logWarn` (not the injected helper logger — task #15 still open) naming host + reason whenever the advanced-settings channel is unreadable or the host is not fully connected.
  - Acceptance shape: post-47 esx04 shows either all 42 controls evaluated (host connected during cycle) or a loud heavily-unreadable cycle (disconnected) — both honest; never again a 6-control score. Other hosts unchanged. Task #12 (SSL trust) remains out of scope. validate-sdk clean; pak-compare vs build 46: 0 BLOCKING / 0 WARNING / 0 INFO.

## 1.0.0.46 (2026-06-10)

- fix(adapter): build 46 — three live-forensics fixes, no scoring/SSL-to-vCenter change. (1) Rebuilt against the current `vcfcf-adapter-base.jar` to adopt the framework Suite API stitch SSL fix (factory commit b12ce5c — `SuiteApiStitchClient` now uses `insecureSslContext()` for the localhost Suite API hop; see lessons/suite-api-stitch-ssl-tofu-vs-java-http.md). Rebuild-only adoption, no adapter source change for stitching. (2) Fixed the onTest NPE (`Cannot invoke VCenterApiClient.login() because this.vcApi is null` at `getTester` lambda): the controller invokes Test-connection on a BARE instance, so `configureAdapter` has not run and both `this.vcApi` and `this.config` are null — and the base's `onTest` passes the still-null `this.config` as `cfg`. The tester lambda is now fully self-contained: it derives vCenter host + credentials from the adapter-instance `ResourceConfig` on the `TestParam` (`param.getAdapterConfig().getAdapterInstResource()`) and builds a fresh `VCenterApiClient` per test, never touching instance state. (3) Fixed dead host-walk telemetry: `VSphereClient`/`EsxcliSoapClient` `log.info(...)` breadcrumbs (`vSphere SOAP: N hosts`, `listView(...): RetrieveProperties -> N objectContent`) emitted ZERO lines on devel despite INFO being enabled. Root cause: the adapter's shadow `adapterLogger()` (the logger injected into the helper clients) returned `getAdapterLoggerFactory().getLogger(getClass())` WITHOUT calling `setLevel(CustomLevel.INFO)`. A freshly-obtained factory logger sits below INFO, so every helper `log.info` was filtered out; the adapter's OWN breadcrumbs still appeared because `logInfo()` routes through the framework base's private `adapterLogger()`, which caches a separate handle and explicitly raises it to INFO. The shadow accessor now mirrors the base (`setLevel(INFO)` before returning), so the injected logger is the working, level-configured instance and the SOAP-walk breadcrumbs reach the collector log. validate-sdk clean; pak-compare vs build 45: 0 BLOCKING / 0 WARNING / 0 INFO (framework jar delta is a byte change inside an unchanged path — structurally invisible).

## 1.0.0.45 (2026-06-10)

- fix(framework): build 45 — adopt the framework constructor-stored adapter-kind contract to fix the build-44 install failure (3/3 failed on devel; platform rolled back to 43). Root cause: during pak install the controller instantiates `ComplianceAdapter` BARE via no-arg reflection and calls `describe()` with NO platform injection, so `getAdapterKind()` is null — the build-44 framework-default `onDescribe()` dereferenced that null and NPE'd through `Could not construct adapter describes` / `DistributedTaskInstallUninstallAdapters failed`. Fix (framework commit 1fa1e4b, mirroring v1 `UnlicensedAdapter`): `VcfCfAdapter` now stores the kind key at construction; constructors changed `super()` → `super(ADAPTER_KIND)` and `super(adapterDir, instanceId)` → `super(ADAPTER_KIND, adapterDir, instanceId)`. The framework default `onDescribe()` resolves the kind from the stored key (safe under bare instantiation), so no `onDescribe()` override is restored — this is the path synology/unifi/template rely on. Verified `ADAPTER_KIND`/describe.xml `key`/pak directory name triple all = `vcfcf_compliance` (the `<adaptersHome>/<kind>/conf/describe.xml` token). Rebuilt against current vcfcf-adapter-base.jar (constructor fix). pak-compare vs build 44: 0 BLOCKING / 0 WARNING / 0 INFO. Build-44 collection content is otherwise unchanged.

## 1.0.0.44 (2026-06-09)

- fix(adapter): build 44 — fix vCenter inventory enumeration regression from the build-43 raw-SOAP rewrite. `retrieveViewMembers` and `queryOptions` searched for `<returnval>` as a DIRECT child of the SOAP `<Envelope>` document element, but the returnvals nest under `Envelope > Body > <op>Response` — direct-child search found zero, so every ContainerView walk (hosts/VMs/DVS/DVPG/clusters) and QueryOptions read silently yielded an empty set with no fault or parse error. Added a deep-search `descendantsByLocalName` (the multi-element analogue of the already-deep `firstByLocalName` that single-object reads used, which masked the bug). Added SOAP-walk instrumentation in `VSphereClient`: INFO inventory counts (hosts/VMs/DVS/DVPG/clusters), per-RetrieveProperties objectContent-count log, DEBUG first-object type/value, and a zero-HostSystem WARN. Removed the redundant `onDescribe()` override (framework default in VcfCfAdapter is byte-identical). Rebuilt against current vcfcf-adapter-base.jar (AmbientCredential VCOPS path fix, default onDescribe).

## 1.0.0.41 (2026-06-03)

- feat(adapter): build 41 — VAMI appliance REST reader (vami_api kind) for vCenter SSH/password-policy controls; failed/non-200/absent-field reads fold to UNREADABLE

## 1.0.0.40 (2026-06-03)

- feat(adapter): build 40 — vm_hardware_device_absent / list_empty / vlan_id_not filter styles via vim25; confirmed-read vs failed-fetch distinction (empty ≠ unreadable)

## 1.0.0.39 (2026-06-03)

- feat(adapter): build 39 — not: and (non-empty) advanced_setting comparison modes; absent/unreadable short-circuits before mode helpers

## 1.0.0.38 (2026-06-03)

- feat(adapter): build 38 — service_state recipe reader (esxcli HostService running/policy) for ESXi service-state controls

## 1.0.0.37 (2026-06-03)

- feat(adapter): build 37 — esxcli SSH/firewall/account cluster + list/row-select reader

## 1.0.0.36 (2026-06-03)

- feat(adapter): build 36 — esxcli recipe reader via vCenter session + syslog proof slice

## 1.0.0.35 (2026-06-03)

- feat(adapter): build 35 — HostSystem/VM vim_property coverage expansion (+14 SCG8/+16 SCG9 reclassified) + in-pak UNAUDITED_CONTROLS.md

## 1.0.0.34 (2026-06-03)

- feat(adapter): compliance adapter evaluation + canonical profile normalization

## 1.0.0.32 (2026-05-29)

- feat(adapter): build 32 — ClusterComputeResource vSAN evaluation (2 of 14)

## 1.0.0.31 (2026-05-29)

- feat(adapter): build 31 — DVS/DVPG security policy evaluation via vim25

## 1.0.0.30 (2026-05-29)

- feat(adapter): build 30 — vCenter world aggregate + DVS/DVPG profile_name fix + profile-change scaffolding

## 1.0.0.29 (2026-05-29)

- fix(framework): build 29 — Heatmap empty-groupBy + AlertList pin-to-world

## 1.0.0.28 (2026-05-28)

- fix(adapter): build 28 — VMwareAdapter Instance resolver + multi-line param classifier

## 1.0.0.27 (2026-05-28)

- feat(adapter): build 27 — Phase 2 multi-resource stitching (VM, vCenter, DVS, DVPG)

## 1.0.0.26 (2026-05-28)

- feat(adapter): build 26 — canonical compliance schema, Phase 1 working on devel

## 1.0.0.19 (2026-05-27)

- feat(framework): build 19 — pin self-provider Views at world singletons

## 1.0.0.18 (2026-05-27)

- feat(adapter): build 18 — owning-adapter binding per spec §18 Pass 28

## 1.0.0.17 (2026-05-27)

- feat(adapter): build 17 — content inside adapters.zip for DashboardImporter

## 1.0.0.16 (2026-05-27)

- feat(adapter): build 16 — first-party content layout + lessons

## 1.0.0.15 (2026-05-27)

- fix(adapter): SymptomSets requires >=2 children — split into two SymptomSet refs

## 1.0.0.14 (2026-05-27)

- feat(compliance): build 14 — alerts, dashboard, and pak content bundling

## 1.0.0.12 (2026-05-27)

- fix(adapter): component filter matched 'ESXi' but CSV has 'VMware ESXi'

## 1.0.0.11 (2026-05-27)

- feat(adapter): vSphere SOAP collection via vim25 — real compliance scoring

## 1.0.0.10 (2026-05-27)

- feat(adapter): push properties via suiteAPIClient.getClient() reflection

## 1.0.0.9 (2026-05-27)

- fix(adapter): debug logging confirms stitcher works, ResourceCollection drops foreign data

## 1.0.0.7 (2026-05-27)

- feat(adapter): custom compliance icons — shield with checkmark
- fix(adapter): revert to injected suiteAPIClient, drop Ops credential fields

## 1.0.0.6 (2026-05-27)

- feat(adapter): self-contained Suite API stitcher (bypass Java SDK SuiteAPIClient)

## 1.0.0.5 (2026-05-27)

- feat(adapter): rename profiles, add CIS vSphere 8 + SCG 9.0, dropdown UI
- feat(adapter): Suite API direct property push (bypass ResourceCollection)

## 1.0.0.4 (2026-05-27)

- fix(adapter): use DTO-backed Resources for foreign property push

## 1.0.0.3 (2026-05-27)

- fix(adapter): handle vCenter REST 404 gracefully, fix duplicate counter

## 1.0.0.1 (2026-05-27)

- feat(adapter): bundle CIS 8.0 benchmark CSV + builder profiles support
- feat(adapter): VCF Compliance Adapter — Phase 1 scaffold
