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

		// Query paths: chunked, encoded, every pair covered.
		java.util.List<String> ids = new java.util.ArrayList<>();
		for (int i = 0; i < 45; i++) ids.add("00000000-0000-0000-0000-0000000000" + (10 + i));
		Set<String> keys = new java.util.TreeSet<>();
		for (int i = 0; i < 70; i++) keys.add("esx.c" + i);
		java.util.List<String> paths =
				ComplianceDecisions.latestCompliantPaths(ids, keys, 20, 30);
		T.eq(9, paths.size(), "3 id chunks x 3 key chunks");
		for (String path : paths) {
			T.check(path.startsWith("/api/resources/stats/latest?resourceId="),
					"endpoint");
			T.check(count(path, "resourceId=") <= 20, "<= 20 ids");
			T.check(count(path, "statKey=") <= 30, "<= 30 keys");
			T.check(path.contains("VCF-CF%20Compliance%7Cesx.c"), "encoded");
			T.check(path.length() < 4000, "URL stays small");
		}
		T.check(ComplianceDecisions.latestCompliantPaths(ids, new
				java.util.TreeSet<>(), 20, 30).isEmpty(), "nothing to ask");

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

		System.out.println("ComplianceDecisionsTest: all assertions passed");
	}

	private static int count(String s, String sub) {
		int n = 0;
		for (int i = s.indexOf(sub); i >= 0; i = s.indexOf(sub, i + 1)) n++;
		return n;
	}
}
