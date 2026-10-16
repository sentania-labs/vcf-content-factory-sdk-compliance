package com.vcfcf.adapters.compliance;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Build 58: the SDK-free per-object decisions the adapter runs
 * (review B1, B2, W1, W2, W4). Run from the repo root.
 */
public final class ComplianceDecisionsTest {

	private static final String K = "VCF-CF Compliance|";

	public static void main(String[] args) {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkSelector auto = BenchmarkSelector.auto(all);
		BenchmarkSelector.Kind HOST = BenchmarkSelector.Kind.HOST;

		// ---- decide (B2)
		ComplianceDecisions.Decision d = ComplianceDecisions.decide(auto, HOST,
				"8.0.3", null, all);
		T.eq(ComplianceDecisions.Outcome.SCORE, d.outcome, "8.0 scores");
		T.eq("VMware_SCG_8.0", d.profileName, "8.0 profile");
		d = ComplianceDecisions.decide(auto, HOST, "10.0.0", "VMware_SCG_9.1",
				all);
		T.eq(ComplianceDecisions.Outcome.NO_BENCHMARK, d.outcome,
				"readable unmapped version is no-benchmark even with history");
		d = ComplianceDecisions.decide(auto, HOST, null, "VMware_SCG_8.0", all);
		T.eq(ComplianceDecisions.Outcome.SCORE, d.outcome,
				"unreadable version reuses the last benchmark applied");
		T.check(d.reusedPrevious, "flagged as reused");
		T.eq("VMware_SCG_8.0", d.profileName, "reused profile");
		T.eq("SCG_8.0", d.bucket, "reused bucket");
		d = ComplianceDecisions.decide(auto, HOST, null, null, all);
		T.eq(ComplianceDecisions.Outcome.VERSION_UNREADABLE, d.outcome,
				"unreadable, no history");
		d = ComplianceDecisions.decide(auto, HOST, "garbage",
				"no benchmark for ESX 10.0", all);
		T.eq(ComplianceDecisions.Outcome.VERSION_UNREADABLE, d.outcome,
				"a no-benchmark label is not a reusable benchmark");

		// ---- payloads (B2, W2)
		Map<String, Double> nb = ComplianceDecisions.noBenchmarkStats();
		T.near(1, nb.get(K + "no_benchmark"), "nb flag");
		T.near(0, nb.get(K + "non_compliant"), "nb not nc");
		for (String c : new String[] {"total_count", "pass_count",
				"fail_count", "unreadable_count"}) {
			T.near(0, nb.get(K + c), "nb zeroes " + c);
			T.near(0, ComplianceDecisions.nothingEvaluatedStats().get(K + c),
					"nothing-evaluated zeroes " + c);
		}
		T.check(!nb.containsKey(K + "score"), "nb never pushes a score");
		Map<String, Double> vu = ComplianceDecisions.versionUnreadableStats();
		// Build 95: nothing readable pushes the flag only (no score 0, no
		// non_compliant, no counters); build 65's collection_failed = 1
		// stays, and no invented unreadable_count.
		T.near(1, vu.get(ComplianceDecisions.HAS_UNREADABLE), "flagged");
		T.check(!vu.containsKey(K + "non_compliant"), "no nc pushed");
		T.check(!vu.containsKey(K + "score"), "no score pushed");
		T.near(1, vu.get(K + "collection_failed"), "collection_failed = 1");
		T.check(!vu.containsKey(K + "unreadable_count"),
				"no invented unreadable_count");
		T.near(0, nb.get(K + "collection_failed"), "nb collection ok");
		T.near(0, ComplianceDecisions.nothingEvaluatedStats().get(
				K + "collection_failed"), "nothing-evaluated collection ok");

		ControlEvaluator.ComplianceResult allUnread =
				new ControlEvaluator.ComplianceResult("h", 0, 0, 0, 3,
						ControlEvaluator.score(0, 0),
						Arrays.asList(new ControlEvaluator.ControlResult(
								"esx.x", "(unreadable)", "5", false, "d", true)));
		Map<String, Double> cs = ComplianceDecisions.complianceStats(allUnread);
		// Build 95: all unreadable = nothing readable: only the unreadable
		// signals go out, the last read values stay.
		T.check(!cs.containsKey(K + "score"), "all unreadable: no score");
		T.near(3, cs.get(K + "unreadable_count"), "unreadable counted apart");
		T.near(1, cs.get(K + "collection_failed"),
				"all unreadable = collection failed");
		T.near(1, cs.get(ComplianceDecisions.HAS_UNREADABLE), "flagged");
		T.check(!cs.containsKey(K + "pass_count"), "no pass_count");
		T.check(!cs.containsKey(K + "fail_count"), "no fail_count");
		T.check(!cs.containsKey(K + "non_compliant"), "no non_compliant");
		// Build 95: an unreadable control is not pushed (was -1).
		T.check(!cs.containsKey(K + "esx.x|Compliant"),
				"unreadable control not pushed");

		// Build 95 (point 7): partly unreadable scores over what was read;
		// fail and unreadable stay apart.
		ControlEvaluator.ComplianceResult partial =
				new ControlEvaluator.ComplianceResult("h", 7, 1, 8, 2,
						ControlEvaluator.score(7, 1), new java.util.ArrayList<>());
		Map<String, Double> ps = ComplianceDecisions.complianceStats(partial);
		T.near(87.5, ps.get(K + "score"), "7 pass of 8 read (was 70)");
		T.near(1, ps.get(K + "fail_count"), "fail_count = evaluated failures");
		T.near(2, ps.get(K + "unreadable_count"), "unreadable kept separate");
		T.near(1, ps.get(K + "non_compliant"), "non-compliant");
		T.near(0, ps.get(K + "collection_failed"),
				"partial read: collection did not fail");
		// Nothing attempted: still no score (never a placeholder).
		ControlEvaluator.ComplianceResult none =
				new ControlEvaluator.ComplianceResult("h", 0, 0, 0, 0,
						ControlEvaluator.score(0, 0), new java.util.ArrayList<>());
		T.check(!ComplianceDecisions.complianceStats(none).containsKey(
				K + "score"), "nothing attempted: no score");

		// ---- stale-control cleanup (build 59)
		BenchmarkProfile p91 = all.get("VMware_SCG_9.1");
		Set<String> union = ComplianceDecisions.candidateControlIds(HOST, null,
				all.values());
		Set<String> cand91 = ComplianceDecisions.candidateControlIds(HOST, p91,
				all.values());
		T.check(!cand91.isEmpty() && union.containsAll(cand91),
				"candidates are bundled controls");
		String inside = null;
		for (BenchmarkProfile.Control c : p91.hostControls()) {
			if (BenchmarkSelector.evaluatedFor(HOST, c)) {
				T.check(!cand91.contains(c.controlId),
						"current benchmark's controls are never candidates");
				inside = c.controlId;
			}
		}
		String outside = cand91.iterator().next();
		String outsideAtMinus1 = null, outsideAt1 = null;
		for (String id : cand91) {
			if (!id.equals(outside) && outsideAtMinus1 == null) outsideAtMinus1 = id;
			else if (!id.equals(outside) && outsideAt1 == null) outsideAt1 = id;
		}
		Map<String, Double> latest = new HashMap<>();
		latest.put(outside, 0.0);            // stale 0 outside: cleaned
		latest.put(inside, 0.0);             // live failure inside: untouched
		latest.put(outsideAtMinus1, -1.0);   // already cleaned: untouched
		latest.put(outsideAt1, 1.0);         // stale pass: untouched
		Set<String> stale = ComplianceDecisions.staleZeroControls(cand91, latest);
		T.eq(new java.util.TreeSet<>(Arrays.asList(outside)), stale,
				"only a stale 0 outside the benchmark flips to -1");
		T.check(ComplianceDecisions.staleZeroControls(cand91, null).isEmpty(),
				"failed bulk read cleans nothing");
		T.check(ComplianceDecisions.staleZeroControls(cand91, new HashMap<>())
				.isEmpty(), "keys the object never had are never created");
		for (Double v : ComplianceDecisions.orphanStats(stale).values()) {
			T.near(-1, v, "cleaned value is -1");
		}
		T.eq("esx.x", ComplianceDecisions.controlIdOfCompliantKey(
				"VCF-CF Compliance|esx.x|Compliant"), "parse key");
		T.eq(null, ComplianceDecisions.controlIdOfCompliantKey(
				"VCF-CF Compliance|Rollup|Host|scored"), "non-Compliant key");
		T.eq(null, ComplianceDecisions.controlIdOfCompliantKey(
				"VCF-CF Compliance|score"), "aggregate key");

		// Query paths sized by URL length (build 60): every path within the
		// budget, every (id, key) pair covered exactly once, and a VM-sized
		// query (one candidate key) packs ~100+ objects per request.
		java.util.List<String> vmIds = new java.util.ArrayList<>();
		for (int i = 0; i < 5000; i++) {
			vmIds.add(String.format("00000000-0000-0000-0000-%012d", i));
		}
		Set<String> oneKey = new java.util.TreeSet<>(Arrays.asList(
				"vm.transparentpagesharing-inter-vm-enabled"));
		java.util.List<String> vmPaths = ComplianceDecisions.latestCompliantPaths(
				vmIds, oneKey, ComplianceDecisions.URL_BUDGET);
		T.check(vmPaths.size() <= 50,
				"5000 VMs x 1 key in <= 50 requests, got " + vmPaths.size());
		assertCoverage(vmPaths, vmIds, oneKey);

		java.util.List<String> hostIds = vmIds.subList(0, 300);
		Set<String> manyKeys = new java.util.TreeSet<>(union);   // 86 host keys
		java.util.List<String> hostPaths = ComplianceDecisions.latestCompliantPaths(
				hostIds, manyKeys, ComplianceDecisions.URL_BUDGET);
		assertCoverage(hostPaths, hostIds, manyKeys);
		for (String path : hostPaths) {
			T.check(path.startsWith("/api/resources/stats/latest?resourceId="),
					"endpoint");
			T.check(path.contains("VCF-CF%20Compliance%7Cesx."), "encoded");
		}
		T.check(ComplianceDecisions.latestCompliantPaths(vmIds, new
				java.util.TreeSet<>(), ComplianceDecisions.URL_BUDGET).isEmpty(),
				"nothing to ask");

		// Build 70: overlay-demoted controls stay cleanup candidates, so a
		// Compliant = 0 pushed by builds 57 to 69 for a standard-switch
		// control on a DVS is retired (-1), never left open.
		Set<String> dvsCand = ComplianceDecisions.candidateControlIds(
				BenchmarkSelector.Kind.VDS, all.get("VMware_SCG_9.1"),
				all.values());
		for (String id : new String[] {
				"vds.network-reject-forged-transmit-standardswitch",
				"vds.network-reject-mac-changes-standardswitch",
				"vds.network-reject-promiscuous-mode-standardswitch",
				"vds.network-standard-reject-forged-transmit",
				"vds.network-standard-reject-mac-changes",
				"vds.network-standard-reject-promiscuous-mode"}) {
			T.check(dvsCand.contains(id), "cleanup candidate on vDS: " + id);
			Map<String, Double> old = new HashMap<>();
			old.put(id, 0.0);
			T.eq(java.util.Collections.singleton(id),
					ComplianceDecisions.staleZeroControls(dvsCand, old),
					"old 0 for " + id + " flips to -1");
		}

		// Build 72: vds.network-reset-port (moved to the portgroup) stays a
		// vDS cleanup candidate, so any lingering 0 on a switch is retired.
		T.check(!ProfileSetTest.find(all.get("VMware_SCG_9.0").controls,
				"dvpg.network-reset-port").isDvsControl(), "moved off vDS");
		T.check(dvsCand.contains("vds.network-reset-port"),
				"retired vds.network-reset-port is a vDS cleanup candidate");
		Map<String, Double> oldReset = new HashMap<>();
		oldReset.put("vds.network-reset-port", 0.0);
		T.eq(java.util.Collections.singleton("vds.network-reset-port"),
				ComplianceDecisions.staleZeroControls(dvsCand, oldReset),
				"old reset-port 0 on a vDS flips to -1");
		Map<String, Double> unread = new HashMap<>();
		unread.put("vds.network-reset-port", -1.0);
		T.check(ComplianceDecisions.staleZeroControls(dvsCand, unread).isEmpty(),
				"the -1 builds 57-71 actually pushed is left alone");
		Set<String> pgCand = ComplianceDecisions.candidateControlIds(
				BenchmarkSelector.Kind.PORTGROUP, all.get("VMware_SCG_9.0"),
				all.values());
		T.check(!pgCand.contains("dvpg.network-reset-port"),
				"scored on the portgroup under 9.0: pushed live, not cleaned");

		// ---- benchmark memory (B2, N3): only restart / edit wipe it
		LastBenchmarkMemory mem = new LastBenchmarkMemory();
		String key = LastBenchmarkMemory.key(HOST, "host-1");
		T.eq(null, mem.record(key, "VMware_SCG_8.0"), "first record");
		T.eq("VMware_SCG_8.0", mem.record(key, "VMware_SCG_9.0"),
				"record returns previous");
		T.eq("VMware_SCG_9.0", mem.previous(key), "remembered");
		mem.clear();
		T.eq(null, mem.previous(key), "instance edit clears");

		// ---- VM follows host (W4)
		Map<String, String> hostVersions = new HashMap<>();
		hostVersions.put("host-1", "8.0.3");
		hostVersions.put("host-2", null);
		int[] reads = {0};
		T.eq("8.0.3", ComplianceDecisions.resolveVmHostVersion("host-1",
				hostVersions, m -> { reads[0]++; return "9.1.1"; }), "from map");
		T.eq(null, ComplianceDecisions.resolveVmHostVersion("host-2",
				hostVersions, m -> { reads[0]++; return "9.1.1"; }),
				"known-unreadable host stays unreadable");
		T.eq("9.1.1", ComplianceDecisions.resolveVmHostVersion("host-3",
				hostVersions, m -> { reads[0]++; return "9.1.1"; }),
				"missing host read once");
		T.eq("9.1.1", ComplianceDecisions.resolveVmHostVersion("host-3",
				hostVersions, m -> { reads[0]++; return "x"; }), "cached");
		T.eq(1, reads[0], "one fallback read");
		T.eq(null, ComplianceDecisions.resolveVmHostVersion(null, hostVersions,
				m -> "9.1.1"), "no host -> unreadable");

		// ---- vCenter match (B1)
		Map<String, String> byUuid = new LinkedHashMap<>();
		Map<String, String> byUrl = new LinkedHashMap<>();
		byUuid.put("uuid-a", "A");
		byUrl.put("vcsa.site1.lab", "A");
		byUrl.put("vcsa.site2.lab", "B");
		T.eq("A", ComplianceDecisions.matchVCenter("uuid-a", byUuid, byUrl,
				"vcsa.site2.lab"), "UUID wins over URL");
		T.eq(null, ComplianceDecisions.matchVCenter("uuid-z", byUuid, byUrl,
				"vcsa.site1.lab"), "known UUID not indexed -> null, no URL guess");
		T.eq("B", ComplianceDecisions.matchVCenter(null, byUuid, byUrl,
				"VCSA.site2.lab"), "UUID unreadable -> exact URL (any case)");
		T.eq(null, ComplianceDecisions.matchVCenter(null, byUuid, byUrl,
				"vcsa"), "no prefix match");
		Map<String, String> single = new LinkedHashMap<>();
		single.put("other.lab", "ONLY");
		T.eq(null, ComplianceDecisions.matchVCenter(null, new HashMap<>(),
				single, "mine.lab"), "no singleton fallback");

		// ---- ComplianceWorld link (build 82; no cache since build 83)
		java.util.List<String> calls = new java.util.ArrayList<>();
		int[] lookups = {0};
		java.util.function.Supplier<String> world = () -> {
			lookups[0]++; return "w-1"; };
		java.util.function.Supplier<String> noWorld = () -> {
			lookups[0]++; return null; };
		java.util.function.BiPredicate<String, String> ok = (p, c) -> {
			calls.add(p + ">" + c); return true; };
		java.util.function.BiPredicate<String, String> fail = (p, c) -> {
			calls.add(p + ">" + c); return false; };

		ComplianceDecisions.WorldLink wl = ComplianceDecisions.linkWorld(
				"vc-a", world, ok);
		T.eq(ComplianceDecisions.LinkOutcome.ACCEPTED, wl.outcome,
				"add accepted");
		T.eq("w-1", wl.worldId, "world id reported");
		T.eq("w-1>vc-a", calls.get(0), "parent world, child own vCenter");
		T.eq(1, lookups[0], "one lookup");

		wl = ComplianceDecisions.linkWorld("vc-a", world, ok);
		T.eq(ComplianceDecisions.LinkOutcome.ACCEPTED, wl.outcome,
				"re-asserted next cycle");
		T.eq(2, lookups[0], "world looked up again every cycle (no cache)");
		T.eq(2, calls.size(), "add re-asserted every cycle");

		wl = ComplianceDecisions.linkWorld(null, world, ok);
		T.eq(ComplianceDecisions.LinkOutcome.NO_VCENTER, wl.outcome,
				"no own vCenter -> skip");
		T.eq(null, wl.worldId, "no world id on skip");
		T.eq(2, calls.size(), "nothing linked without own vCenter");
		T.eq(2, lookups[0], "no lookup without own vCenter");
		wl = ComplianceDecisions.linkWorld("  ", world, ok);
		T.eq(ComplianceDecisions.LinkOutcome.NO_VCENTER, wl.outcome,
				"blank vCenter id -> skip");
		T.eq(2, lookups[0], "no lookup for blank vCenter id");

		wl = ComplianceDecisions.linkWorld("vc-a", noWorld, ok);
		T.eq(ComplianceDecisions.LinkOutcome.NO_WORLD, wl.outcome,
				"world not created yet -> skip");
		T.eq(2, calls.size(), "no add without a world id");
		wl = ComplianceDecisions.linkWorld("vc-a", () -> " ", ok);
		T.eq(ComplianceDecisions.LinkOutcome.NO_WORLD, wl.outcome,
				"blank world id -> skip");
		T.eq(2, calls.size(), "no add with a blank world id");

		wl = ComplianceDecisions.linkWorld("vc-a", world, fail);
		T.eq(ComplianceDecisions.LinkOutcome.ADD_FAILED, wl.outcome,
				"add failed");
		T.eq("w-1", wl.worldId, "failed world id reported");
		// A recreated world (new id) is picked up on the very next cycle
		// because nothing is carried over, whatever the add returned.
		wl = ComplianceDecisions.linkWorld("vc-a", () -> "w-2", ok);
		T.eq(ComplianceDecisions.LinkOutcome.ACCEPTED, wl.outcome,
				"next cycle uses the current world");
		T.eq("w-2>vc-a", calls.get(calls.size() - 1), "linked to new world");

		// ---- build 87 (review W1): a partly unreadable host is named at INFO
		T.check(!ComplianceDecisions.hostScoreLineAtInfo(0),
				"fully read host: score line at DEBUG");
		T.check(ComplianceDecisions.hostScoreLineAtInfo(1),
				"one unreadable control: score line at INFO");
		T.check(ComplianceDecisions.hostScoreLineAtInfo(19),
				"many unreadable controls: score line at INFO");

		build88PodGuestIds();
		build88ResourcePages();
		build88SourcePins();

		System.out.println("ComplianceDecisionsTest: all assertions passed");
	}

	/**
	 * Build 88 review W2: a resource list that parsed but is short holds
	 * the kind back; a missing resourceList is not "0 resources".
	 */
	private static void build88ResourcePages() {
		ComplianceDecisions.ResourcePage C =
				ComplianceDecisions.ResourcePage.COMPLETE;
		ComplianceDecisions.ResourcePage N =
				ComplianceDecisions.ResourcePage.NEXT_PAGE;
		ComplianceDecisions.ResourcePage I =
				ComplianceDecisions.ResourcePage.INCOMPLETE;
		// Missing resourceList.
		T.eq(I, ComplianceDecisions.resourcePageOutcome(false, null, 0, 0, 0),
				"no resourceList, no pageInfo: incomplete");
		T.eq(I, ComplianceDecisions.resourcePageOutcome(false, 25L, 0, 0, 0),
				"no resourceList with a total: incomplete");
		T.eq(C, ComplianceDecisions.resourcePageOutcome(false, 0L, 0, 0, 0),
				"no resourceList, total 0: genuinely empty");
		T.eq(I, ComplianceDecisions.resourcePageOutcome(false, 0L, 5, 0, 1),
				"no resourceList on a later page: incomplete");
		// totalCount exceeds the rows returned.
		T.eq(N, ComplianceDecisions.resourcePageOutcome(true, 12500L, 10000,
				10000, 0), "first of two pages: read the next");
		T.eq(C, ComplianceDecisions.resourcePageOutcome(true, 12500L, 12500,
				2500, 1), "second page completes the list");
		T.eq(I, ComplianceDecisions.resourcePageOutcome(true, 12500L, 10000,
				0, 1), "empty page before the total: incomplete");
		T.eq(I, ComplianceDecisions.resourcePageOutcome(true, 10001L, 1000,
				1000, ComplianceDecisions.MAX_RESOURCE_PAGES - 1),
				"page cap reached short of the total: incomplete");
		T.eq(N, ComplianceDecisions.resourcePageOutcome(true, 1001L, 1000,
				1000, 0),
				"server capped the page below pageSize: keep paging");
		// Complete lists.
		T.eq(C, ComplianceDecisions.resourcePageOutcome(true, 25L, 25, 25, 0),
				"one page, all rows");
		T.eq(C, ComplianceDecisions.resourcePageOutcome(true, 0L, 0, 0, 0),
				"empty list, total 0");
		T.eq(C, ComplianceDecisions.resourcePageOutcome(true, null, 25, 25, 0),
				"no pageInfo: one unpaged list as returned");
		T.eq(10000, ComplianceDecisions.RESOURCE_PAGE_SIZE, "page size");
	}

	/** Build 88: which guest ids are vSphere Pods; when a kind is pushable. */
	private static void build88PodGuestIds() {
		for (String id : new String[] {"crxPod1Guest", "crxSys1Guest",
				"CRXPOD1GUEST", "CrxPod1Guest", "crxFuture2Guest", "crx",
				" crxPod1Guest"}) {
			T.check(ComplianceDecisions.isPodGuestId(id), "Pod: '" + id + "'");
		}
		for (String id : new String[] {null, "", "  ", "otherLinux64Guest",
				"vmwarePhoton64Guest", "windows2022srvNext_64Guest",
				"centos64Guest", "xcrxPod1Guest", "cr", "rhel9_64Guest"}) {
			T.check(!ComplianceDecisions.isPodGuestId(id),
					"not a Pod: '" + id + "'");
		}
		T.check(ComplianceDecisions.kindPushable(true, false),
				"stitcher and resource list read: pushable");
		T.check(!ComplianceDecisions.kindPushable(true, true),
				"resource list failed: not pushable (held back)");
		T.check(!ComplianceDecisions.kindPushable(false, false),
				"no stitcher: not pushable");
	}

	/**
	 * Build 88: the adapter wiring needs the SDK jar this runner leaves off
	 * the classpath, so the order that makes the scope rule hold is pinned
	 * in the source: Pods skipped before matching, unmatched objects
	 * recorded and skipped before any read or decision, every kind gated on
	 * a readable VCF Ops resource list, and the guest id read in the bulk VM
	 * enumeration.
	 */
	private static void build88SourcePins() {
		String ca = read("src/com/vcfcf/adapters/compliance/ComplianceAdapter.java");

		String vms = body(ca, "private void collectVms(");
		inOrder(vms, "collectVms",
				"kindPushable(BenchmarkSelector.Kind.VM, \"VirtualMachine\", rollup)",
				"if (ComplianceDecisions.isPodGuestId(vm.guestId)) { rollup.recordSkippedPod();",
				"continue; } cs.vms++;",
				"if (!pushable) continue;",
				"stitcher.matchVm(vm.name, vm.moid); if (he == null) { rollup.recordUnmatched(BenchmarkSelector.Kind.VM, vm.name, vm.moid); continue; }",
				"vmHostVersion(vm, hostVersions)",
				"decide(selector, BenchmarkSelector.Kind.VM",
				"vsphere.getVmExtraConfig(vm.moRef)",
				"rollup.recordEvaluated(BenchmarkSelector.Kind.VM");
		noReadBefore(vms, "collectVms", "stitcher.matchVm(");

		String hosts = body(ca, "private java.util.Map<String, String> collectHosts(");
		inOrder(hosts, "collectHosts",
				"kindPushable(BenchmarkSelector.Kind.HOST, \"HostSystem\", rollup)",
				"if (!pushable) continue;",
				"stitcher.matchHost(hostName, hostId); if (he == null) { rollup.recordUnmatched(BenchmarkSelector.Kind.HOST, hostName, hostId); continue; }",
				"vsphere.getHostProductVersion(hostInfo.moRef)",
				"decide(selector, BenchmarkSelector.Kind.HOST",
				"vsphere.getAdvancedSettings(hostInfo.moRef)",
				"rollup.recordEvaluated(BenchmarkSelector.Kind.HOST");
		noReadBefore(hosts, "collectHosts", "stitcher.matchHost(");

		String vc = body(ca, "private ComplianceStitcher.HostEntry collectVCenter(");
		inOrder(vc, "collectVCenter",
				"rollup.recordUnmatched(BenchmarkSelector.Kind.VCENTER, resourceName, moid); return null; }",
				"decide(selector, BenchmarkSelector.Kind.VCENTER",
				"vsphere.getVCenterAdvancedSettings()",
				"rollup.recordEvaluated(BenchmarkSelector.Kind.VCENTER");

		String vim = body(ca, "private void collectVimObject(");
		inOrder(vim, "collectVimObject",
				"if (he == null) { rollup.recordUnmatched(kind, name, moid); return; }",
				"decide(selector, kind, moid",
				"rollup.recordEvaluated(kind");
		noReadBefore(vim, "collectVimObject", "rollup.recordUnmatched(kind");

		inOrder(body(ca, "private void collectDvs("), "collectDvs",
				"vsphere.getDvSwitches()",
				"if (!kindPushable(BenchmarkSelector.Kind.VDS, \"VmwareDistributedVirtualSwitch\", rollup)) { return; }",
				"collectVimObject(");
		inOrder(body(ca, "private void collectDvpg("), "collectDvpg",
				"vsphere.getDvPortgroups()",
				"if (!kindPushable(BenchmarkSelector.Kind.PORTGROUP, \"DistributedVirtualPortgroup\", rollup)) { return; }",
				"collectVimObject(");
		inOrder(body(ca, "private void collectClusters("), "collectClusters",
				"vsphere.getClusters()",
				"if (!kindPushable(BenchmarkSelector.Kind.CLUSTER, \"ClusterComputeResource\", rollup)) { return; }",
				"collectVimObject(");

		inOrder(body(ca, "private boolean kindPushable("), "kindPushable",
				"boolean failed = present && cycle.stitcher.loadFailed(resourceKind);",
				"if (ComplianceDecisions.kindPushable(present, failed)) { return true; }",
				"rollup.markIncomplete(kind);",
				"return false;");

		inOrder(body(ca, "private void collectWorldCycle("), "collectWorldCycle",
				"String line = rollup.unmatchedLogLine(k); if (line != null) { logInfo(line); }",
				"pushRollup(vcEntry, rollup);");

		String vs = read("src/com/vcfcf/adapters/compliance/VSphereClient.java");
		inOrder(body(vs, "public List<VmInfo> getVms("), "getVms",
				"\"name\", \"runtime.host\", \"config.guestId\");",
				"if (rows == null) {",
				"\"name\", \"runtime.host\");",
				"row.values.get(\"runtime.host\"), true, row.values.get(\"config.guestId\"))");

		String st = read("src/com/vcfcf/adapters/compliance/ComplianceStitcher.java");
		String fr = body(st, "private List<SimpleJson> fetchResources(");
		inOrder(fr, "fetchResources",
				"failedLoads.add(resourceKind);",
				"for (int page = 0; ; page++) {",
				"\"&pageSize=\" + ComplianceDecisions.RESOURCE_PAGE_SIZE + \"&page=\" + page);",
				"if (parsed == null || parsed.isNull()) {",
				"return out; }",
				"boolean hasList = list != null && list.isList();",
				"int rows = hasList ? list.size() : 0;",
				"collected += rows;",
				"SimpleJson total = parsed.path(\"pageInfo.totalCount\"); Long totalCount = total.isNull() ? null : total.asLong();",
				// Build 96 (issue #52): the kind's history goes in, and an
				// unconfirmed empty list is held back like INCOMPLETE
				// (Build96StitcherTest runs the loop itself).
				"ComplianceDecisions.resourcePageOutcome(hasList, totalCount, collected, rows, page, previousCount, heldEmpty);",
				"if (next == ComplianceDecisions.ResourcePage.COMPLETE) { failedLoads.remove(resourceKind); lastCompleteCount.put(resourceKind, collected);",
				"return out; }",
				"if (next == ComplianceDecisions.ResourcePage .EMPTY_UNCONFIRMED) { emptyHeldBack.add(resourceKind);",
				"return out; }",
				"if (next == ComplianceDecisions.ResourcePage.INCOMPLETE) {",
				"return out; }");
		// The failed mark is cleared in exactly one place: a complete list.
		T.eq(1, count(fr, "failedLoads.remove("),
				"fetchResources clears the failed mark only on COMPLETE");
		T.check(body(st, "public boolean loadFailed(").equals(
				"return failedLoads.contains(resourceKind);"), "loadFailed body");
	}

	/**
	 * No vCenter read ({@code vsphere.}) occurs in {@code src} before
	 * {@code marker}: an unmatched object costs no read. The one listing
	 * call ({@code vsphere.getHosts()} / {@code getVms()}) precedes the loop
	 * and is allowed.
	 */
	private static void noReadBefore(String src, String where, String marker) {
		int at = src.indexOf(marker);
		T.check(at >= 0, where + ": found " + marker);
		String head = src.substring(0, at)
				.replace("vsphere.getHosts()", "")
				.replace("vsphere.getVms()", "");
		T.check(!head.contains("vsphere."),
				where + ": no vCenter read before " + marker);
	}

	/** Each fragment occurs in {@code src}, in this order. */
	private static void inOrder(String src, String where, String... fragments) {
		int from = 0;
		for (String f : fragments) {
			int at = src.indexOf(f, from);
			T.check(at >= 0, where + ": expected, in order: " + f);
			from = at + f.length();
		}
	}

	private static String read(String path) {
		try {
			return new String(java.nio.file.Files.readAllBytes(
					java.nio.file.Paths.get(path)),
					java.nio.charset.StandardCharsets.UTF_8);
		} catch (java.io.IOException e) {
			throw new AssertionError("read " + path + ": " + e);
		}
	}

	/**
	 * The body of the first method whose declaration starts with
	 * {@code signature}, comments removed and whitespace collapsed (as in
	 * EsxcliCycleCacheTest).
	 */
	private static String body(String src, String signature) {
		int at = src.indexOf(signature);
		T.check(at >= 0, "found " + signature);
		int open = src.indexOf('{', at);
		int depth = 0;
		int i = open;
		for (; i < src.length(); i++) {
			char ch = src.charAt(i);
			if (ch == '{') depth++;
			else if (ch == '}' && --depth == 0) break;
		}
		String b = src.substring(open + 1, i);
		b = b.replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("//[^\\n]*", "");
		return b.replaceAll("\\s+", " ").trim();
	}

	/** Every path within budget; every (id, key) pair exactly once. */
	private static void assertCoverage(java.util.List<String> paths,
			java.util.List<String> ids, Set<String> keys) {
		Map<String, Integer> pairs = new HashMap<>();
		for (String path : paths) {
			T.check(path.length() <= ComplianceDecisions.URL_BUDGET,
					"path within URL budget: " + path.length());
			java.util.List<String> pIds = new java.util.ArrayList<>();
			java.util.List<String> pKeys = new java.util.ArrayList<>();
			for (String part : path.substring(path.indexOf('?') + 1).split("&")) {
				String v;
				try {
					v = java.net.URLDecoder.decode(part.substring(
							part.indexOf('=') + 1), "UTF-8");
				} catch (java.io.UnsupportedEncodingException e) {
					throw new AssertionError(e);
				}
				if (part.startsWith("resourceId=")) pIds.add(v);
				else if (part.startsWith("statKey=")) {
					pKeys.add(ComplianceDecisions.controlIdOfCompliantKey(v));
				}
			}
			for (String i : pIds) for (String k : pKeys) {
				pairs.merge(i + "/" + k, 1, Integer::sum);
			}
		}
		T.eq(ids.size() * keys.size(), pairs.size(), "all pairs covered");
		for (Integer n : pairs.values()) T.eq(1, n, "each pair once");
	}

	private static int count(String s, String sub) {
		int n = 0;
		for (int i = s.indexOf(sub); i >= 0; i = s.indexOf(sub, i + 1)) n++;
		return n;
	}
}
