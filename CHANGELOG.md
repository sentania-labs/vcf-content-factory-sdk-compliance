# Changelog

## 1.0.0.47 (2026-06-10)

- fix(adapter): build 47 — the honesty build. Closes the build-46 esx04 host-scoped partial-collection regression (root cause: context/investigations/compliance_esx04_partial_collection_2026_06_10.md; predicted by reviewer build-43 WARNING, ControlEvaluator.java:139-150) where a flapping/disconnected host yielded a flattering partial score (83.33 from 6 controls vs baseline 66.67 from 42) because the advanced_setting channel vanished silently from the denominator. Four changes, all on the known-unreadable path only — healthy-host evaluation is byte-identical (pak-compare vs 46: 0/0/0; no describe/content/scoring change for connected hosts). (1) `VSphereClient.getAdvancedSettings()` now THROWS the new typed `AdvancedSettingsUnreadableException` when the `configManager.advancedOption` OptionManager MoRef is null (the disconnected-host signature) instead of returning a silent empty map — distinguishing known-unreadable from known-empty. A host with a live OptionManager and zero options still returns an empty map normally (the legitimate "X or Undefined" allowsUndefined semantics are untouched). (2) `ControlEvaluator.evaluateControlsUnreadable()` folds EVERY advanced_setting control to UNREADABLE (counted in unreadable_count, excluded from the score numerator/denominator) when the channel is known-unreadable — never silently skipped; total attempted = scored + unreadable, always. (3) Connection-state guard in `collectHosts`: reads `runtime.connectionState` via the new `getHostConnectionState()`; on disconnected/notResponding, marks ALL of that host's controls (advanced_setting + vim_property + esxcli) UNREADABLE with one loud WARN naming host + state, rather than scoring any partial subset. A half-connected host never produces a score. (4) Instrumentation: WARNs routed through the FRAMEWORK BASE `logWarn` (not the injected helper logger — task #15 still open) naming host + reason whenever the advanced-settings channel is unreadable or the host is not fully connected. Acceptance shape: post-47 esx04 shows either all 42 controls evaluated (host connected during cycle) or a loud heavily-unreadable cycle (disconnected) — both honest; never again a 6-control score. Other hosts unchanged. Task #12 (SSL trust) remains out of scope. validate-sdk clean; pak-compare vs build 46: 0 BLOCKING / 0 WARNING / 0 INFO.

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
