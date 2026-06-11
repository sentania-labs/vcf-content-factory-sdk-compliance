# Changelog

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
