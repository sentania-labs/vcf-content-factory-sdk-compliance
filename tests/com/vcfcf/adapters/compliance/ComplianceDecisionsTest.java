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
				"unreadable version reuses last cycle's benchmark");
		T.check(d.reusedPrevious, "flagged as reused");
		T.eq("VMware_SCG_8.0", d.profileName, "reused profile");
		T.eq("SCG_8.0", d.bucket, "reused bucket");
		d = ComplianceDecisions.decide(auto, HOST, null, null, all);
		T.eq(ComplianceDecisions.Outcome.VERSION_UNREADABLE, d.outcome,
				"unreadable, no history");
		d = ComplianceDecisions.decide(auto, HOST, "garbage",
				"no benchmark for ESXi 10.0", all);
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
		T.near(1, vu.get(K + "non_compliant"), "version unreadable is nc");
		T.near(0, vu.get(K + "no_benchmark"), "version unreadable not nb");
		T.check(!vu.containsKey(K + "score"), "no score when unreadable");

		ControlEvaluator.ComplianceResult allUnread =
				new ControlEvaluator.ComplianceResult("h", 0, 0, 0, 3, 100.0,
						Arrays.asList(new ControlEvaluator.ControlResult(
								"esx.x", "(unreadable)", "5", false, "d", true)));
		Map<String, Double> cs = ComplianceDecisions.complianceStats(allUnread);
		T.check(!cs.containsKey(K + "score"), "no sentinel score");
		T.near(0, cs.get(K + "pass_count"), "pass zeroed when nothing scored");
		T.near(0, cs.get(K + "fail_count"), "fail zeroed when nothing scored");
		T.near(1, cs.get(K + "non_compliant"), "unreadable -> nc");
		T.near(-1, cs.get(K + "esx.x|Compliant"), "unreadable Compliant=-1");

		// ---- orphan set (W1)
		BenchmarkProfile p80 = all.get("VMware_SCG_8.0");
		BenchmarkProfile p91 = all.get("VMware_SCG_9.1");
		Set<String> union = ComplianceDecisions.orphanControlIds(HOST, null,
				null, all.values(), true);
		Set<String> firstSight91 = ComplianceDecisions.orphanControlIds(HOST,
				null, p91, all.values(), true);
		Set<String> change80to91 = ComplianceDecisions.orphanControlIds(HOST,
				p80, p91, all.values(), false);
		T.check(!union.isEmpty(), "union non-empty");
		for (BenchmarkProfile.Control c : p91.hostControls()) {
			if (BenchmarkSelector.evaluatedFor(HOST, c)) {
				T.check(!firstSight91.contains(c.controlId),
						"current controls kept: " + c.controlId);
				T.check(!change80to91.contains(c.controlId),
						"current controls kept on change: " + c.controlId);
			}
		}
		T.check(union.containsAll(firstSight91), "first sight within union");
		T.check(firstSight91.containsAll(change80to91),
				"a change cleans a subset of the first-sight set");
		for (String id : change80to91) {
			T.check(ProfileSetTest.find(p80.controls, id) != null,
					"change cleans only 8.0 controls: " + id);
		}
		// Previous unresolvable (Custom, label) -> union, self-healing.
		T.eq(firstSight91, ComplianceDecisions.orphanControlIds(HOST, null, p91,
				all.values(), false), "unresolvable previous -> union");
		// No-benchmark object: every bundled control of the kind is cleaned.
		T.eq(union, ComplianceDecisions.orphanControlIds(HOST, null, null,
				all.values(), true), "no benchmark cleans the union");
		Map<String, Double> os = ComplianceDecisions.orphanStats(change80to91);
		for (Double v : os.values()) T.near(-1, v, "orphans are -1");

		// ---- tracker (W1)
		AppliedBenchmarkTracker tr = new AppliedBenchmarkTracker();
		String key = AppliedBenchmarkTracker.key(HOST, "host-1");
		T.check(tr.firstSight(key) && tr.needsCleanup(key, "VMware_SCG_9.1"),
				"new object needs cleanup");
		tr.record(key, "VMware_SCG_9.1");
		T.check(!tr.needsCleanup(key, "VMware_SCG_9.1"), "steady state");
		T.check(tr.needsCleanup(key, "VMware_SCG_8.0"), "change needs cleanup");
		tr.clear();
		T.check(tr.firstSight(key), "instance edit -> first sight again");
		tr.record(key, "VMware_SCG_9.1");
		boolean swept = false;
		for (int i = 0; i < AppliedBenchmarkTracker.RESWEEP_CYCLES; i++) {
			swept |= tr.startCycle();
		}
		T.check(swept && tr.firstSight(key), "periodic re-sweep clears");

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

		System.out.println("ComplianceDecisionsTest: all assertions passed");
	}
}
