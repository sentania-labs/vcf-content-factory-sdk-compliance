package com.vcfcf.adapters.compliance;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Simulated mixed-version vCenter over two collect cycles (owner-approved
 * approach: fake the inventory in tests; the lab runs one ESXi build).
 *
 * <p>Build 58 (review W4): every per-object decision is made by the SAME
 * SDK-free code the adapter calls ({@link ComplianceDecisions#decide},
 * {@link ComplianceDecisions#resolveVmHostVersion}, the payload builders,
 * {@link ComplianceDecisions#orphanControlIds},
 * {@link AppliedBenchmarkTracker}), with the real bundled profiles,
 * evaluator and rollup. Only the SOAP reads and Suite API pushes are
 * simulated (a recording "push" map per object).
 *
 * <p>Cycle 1: vCenter 9.1.1; hosts on ESXi 6.7, 7.0, 8.0 U3, 9.0, 9.1
 * (disconnected, last-known score 50) and unmapped 10.0; VMs on the 6.7,
 * 8.0 U3 and 10.0 hosts; a vDS reporting its own 9.0.0 (ignored) and a
 * portgroup. Cycle 2: the 8.0 host was upgraded to 9.0, the 7.0 host's
 * version read fails (reuses 7.0), and a new host appears whose version
 * cannot be read (unreadable, non-compliant).
 */
public final class MixedVersionSimulationTest {

	private static final String P = ComplianceRollup.PREFIX;
	private static final String K = "VCF-CF Compliance|";

	private final Map<String, BenchmarkProfile> all;
	private final BenchmarkSelector sel;
	private final AppliedBenchmarkTracker tracker = new AppliedBenchmarkTracker();
	// Last pushed stats per object (simulated Suite API).
	private final Map<String, Map<String, Double>> pushed = new HashMap<>();
	private final Map<String, Double> lastKnown = new HashMap<>();
	private final Map<String, Integer> cleaned = new HashMap<>();

	private MixedVersionSimulationTest() {
		all = new BenchmarkLoader().loadAll(".");
		sel = BenchmarkSelector.auto(all);
	}

	public static void main(String[] args) {
		new MixedVersionSimulationTest().run();
		System.out.println("MixedVersionSimulationTest: all assertions passed");
	}

	private void run() {
		String vc = "9.1.1";
		// ---------------- cycle 1
		Map<String, String> hosts = new LinkedHashMap<>();
		hosts.put("host-67", "6.7.0");
		hosts.put("host-70", "7.0.3");
		hosts.put("host-80", "8.0.3");
		hosts.put("host-90", "9.0.0");
		hosts.put("host-91", "9.1.1");
		hosts.put("host-100", "10.0.0");
		Map<String, String> vmHost = new LinkedHashMap<>();
		vmHost.put("vm-a", "host-80");
		vmHost.put("vm-b", "host-100");
		vmHost.put("vm-c", "host-67");
		lastKnown.put("host-91", 50.0);

		ComplianceRollup r1 = cycle(vc, hosts, vmHost, "host-91");
		T.eq("VMware_SCG_6.7", profileName("HOST|host-67"), "6.7 host");
		T.eq("VMware_SCG_7.0", profileName("HOST|host-70"), "7.0 host");
		T.eq("VMware_SCG_8.0", profileName("HOST|host-80"), "8.0 U3 host");
		T.eq("VMware_SCG_9.0", profileName("HOST|host-90"), "9.0 host");
		T.eq("VMware_SCG_9.1", profileName("HOST|host-91"), "9.1 host");
		T.eq("VMware_SCG_8.0", profileName("VM|vm-a"), "VM follows 8.0 host");
		T.eq("VMware_SCG_6.7", profileName("VM|vm-c"), "VM follows 6.7 host");
		T.eq("VMware_SCG_9.1", profileName("VDS|dvs-1"),
				"vDS (own 9.0.0) follows vCenter 9.1");
		T.eq("VMware_SCG_9.1", profileName("PORTGROUP|pg-1"), "pg follows vCenter");

		// No-benchmark payload: flagged and zeroed (W2), not non-compliant.
		Map<String, Double> h100 = pushed.get("HOST|host-100");
		T.near(1, h100.get(K + "no_benchmark"), "10.0 host no_benchmark");
		T.near(0, h100.get(K + "non_compliant"), "10.0 host not nc");
		T.near(0, h100.get(K + "total_count"), "10.0 host total zeroed");
		T.check(!h100.containsKey(K + "score"), "10.0 host no score");
		T.near(1, pushed.get("VM|vm-b").get(K + "no_benchmark"),
				"VM on 10.0 host no_benchmark");
		T.near(1, pushed.get("HOST|host-91").get(K + "non_compliant"),
				"disconnected host non-compliant");

		// First sight: every object cleaned against the bundled union (W1).
		T.check(cleaned.getOrDefault("HOST|host-100", 0) > 0,
				"no-benchmark host cleaned on first sight");

		T.near(2, r1.toStats().get(P + "Benchmark|SCG_6.7|objects"), "6.7");
		T.near(1, r1.toStats().get(P + "Benchmark|SCG_7.0|objects"), "7.0");
		T.near(2, r1.toStats().get(P + "Benchmark|SCG_8.0|objects"), "8.0");
		T.near(1, r1.toStats().get(P + "Benchmark|SCG_9.0|objects"), "9.0");
		T.near(4, r1.toStats().get(P + "Benchmark|SCG_9.1|objects"),
				"9.1: host + vCenter + vDS + portgroup");
		T.near(2, r1.toStats().get(P + "Benchmark|none|objects"), "none");
		T.near(0, r1.toStats().get(P + "Benchmark|unknown|objects"), "unknown");
		T.near(1, r1.toStats().get(P + "Host|no_benchmark"), "host nb");
		T.near(1, r1.toStats().get(P + "VM|no_benchmark"), "vm nb");
		T.near(2, r1.toStats().get(P + "Host|non_compliant"),
				"8.0 host (fail) + 9.1 host (unreadable)");
		T.near(5, r1.toStats().get(P + "Host|scored"), "4 live + 1 stale");
		T.near(1, r1.toStats().get(P + "Host|scored_stale"), "stale host");

		// ---------------- cycle 2
		cleaned.clear();
		hosts.put("host-80", "9.0.0");     // upgraded
		hosts.put("host-70", null);        // version read fails
		hosts.put("host-new", null);       // new, version unreadable
		ComplianceRollup r2 = cycle(vc, hosts, vmHost, "host-91");

		T.eq("VMware_SCG_9.0", profileName("HOST|host-80"), "upgraded host");
		int moved = cleaned.getOrDefault("HOST|host-80", 0);
		Set<String> expect = ComplianceDecisions.orphanControlIds(
				BenchmarkSelector.Kind.HOST, all.get("VMware_SCG_8.0"),
				all.get("VMware_SCG_9.0"), all.values(), false);
		T.eq(expect.size(), moved, "upgrade cleans exactly 8.0-only controls");
		T.eq("VMware_SCG_9.0", profileName("VM|vm-a"), "VM follows upgrade");

		// B2: failed version read reuses the last benchmark, no cleanup.
		T.eq("VMware_SCG_7.0", profileName("HOST|host-70"), "7.0 reused");
		T.check(!cleaned.containsKey("HOST|host-70"), "no cleanup on reuse");
		// B2: unreadable with no history is non-compliant, not no-benchmark.
		Map<String, Double> hn = pushed.get("HOST|host-new");
		T.near(1, hn.get(K + "non_compliant"), "new unreadable host nc");
		T.near(0, hn.get(K + "no_benchmark"), "not no_benchmark");
		T.check(tracker.previous("HOST|host-new") == null,
				"unreadable object not recorded (no cleanup baseline)");
		T.check(!cleaned.containsKey("HOST|host-new"), "no cleanup");

		Map<String, Double> s2 = r2.toStats();
		T.near(1, s2.get(P + "Benchmark|unknown|objects"), "unknown bucket");
		T.near(1, s2.get(P + "Host|no_benchmark"), "only the 10.0 host");
		T.near(3, s2.get(P + "Host|non_compliant"),
				"9.1 unreadable + new unreadable + 9.0 upgraded (fails)");
		// Steady objects are not re-cleaned.
		T.check(!cleaned.containsKey("HOST|host-90"), "no churn when steady");
	}

	/** One simulated collect cycle through the adapter's decision code. */
	private ComplianceRollup cycle(String vcVersion, Map<String, String> hosts,
			Map<String, String> vmHost, String disconnectedHost) {
		ComplianceRollup rollup = new ComplianceRollup();
		Map<String, String> hostVersions = new HashMap<>();
		for (Map.Entry<String, String> h : hosts.entrySet()) {
			hostVersions.put(h.getKey(), h.getValue());
			BenchmarkSelector.Kind kind = BenchmarkSelector.Kind.HOST;
			ComplianceDecisions.Decision d = decide(kind, h.getKey(),
					BenchmarkSelector.governingVersion(kind, vcVersion,
							h.getValue()));
			if (d == null) {
				Double last = lastKnown.get(h.getKey());
				if (last != null) rollup.recordStaleScore(kind, last);
				rollup.recordVersionUnreadable(kind);
				continue;
			}
			if (d.outcome == ComplianceDecisions.Outcome.NO_BENCHMARK) {
				noBenchmark(kind, h.getKey(), d, rollup);
				continue;
			}
			List<BenchmarkProfile.Control> slice = d.profile.hostControls();
			ControlEvaluator.ComplianceResult cr;
			if (h.getKey().equals(disconnectedHost)) {
				cr = merge(ControlEvaluator.evaluateControlsUnreadable(slice,
						h.getKey()), unreadableVim(slice, h.getKey()));
			} else {
				Map<String, String> adv = passingSettings(slice);
				if (h.getKey().equals("host-80")) {
					adv.put("Security.AccountLockFailures", "99");
				}
				cr = ControlEvaluator.evaluateControls(slice, adv, h.getKey());
				T.check(cr.totalCount > 0, h.getKey() + " scored something");
				T.eq(h.getKey().equals("host-80") ? 1 : 0, cr.failCount,
						h.getKey() + " failures");
			}
			rollup.recordEvaluated(kind, d.bucket, cr.totalCount, cr.failCount,
					cr.unreadableCount, cr.score);
			if (cr.totalCount == 0) {
				Double last = lastKnown.get(h.getKey());
				if (last != null) rollup.recordStaleScore(kind, last);
			}
			scored(kind, h.getKey(), d, cr);
		}
		for (Map.Entry<String, String> v : vmHost.entrySet()) {
			BenchmarkSelector.Kind kind = BenchmarkSelector.Kind.VM;
			String hv = ComplianceDecisions.resolveVmHostVersion(v.getValue(),
					hostVersions, m -> null);
			ComplianceDecisions.Decision d = decide(kind, v.getKey(),
					BenchmarkSelector.governingVersion(kind, vcVersion, hv));
			if (d == null) {
				rollup.recordVersionUnreadable(kind);
				continue;
			}
			if (d.outcome == ComplianceDecisions.Outcome.NO_BENCHMARK) {
				noBenchmark(kind, v.getKey(), d, rollup);
				continue;
			}
			ControlEvaluator.ComplianceResult cr =
					ControlEvaluator.evaluateControls(d.profile.vmControls(),
							passingSettings(d.profile.vmControls()), v.getKey());
			T.eq(0, cr.failCount, v.getKey() + " no failures");
			rollup.recordEvaluated(kind, d.bucket, cr.totalCount, cr.failCount,
					cr.unreadableCount, cr.score);
			scored(kind, v.getKey(), d, cr);
		}
		String[][] vcObjects = {{"VCENTER", "vcenter"}, {"VDS", "dvs-1"},
				{"PORTGROUP", "pg-1"}};
		for (String[] o : vcObjects) {
			BenchmarkSelector.Kind kind = BenchmarkSelector.Kind.valueOf(o[0]);
			ComplianceDecisions.Decision d = decide(kind, o[1],
					BenchmarkSelector.governingVersion(kind, vcVersion, "9.0.0"));
			rollup.recordEvaluated(kind, d.bucket, 1, 0, 0, 100.0);
			tracker.record(AppliedBenchmarkTracker.key(kind, o[1]),
					d.profileName);
		}
		return rollup;
	}

	/**
	 * decide() as the adapter calls it; a VERSION_UNREADABLE outcome is
	 * pushed (payload recorded) and returned as null to the caller.
	 */
	private ComplianceDecisions.Decision decide(BenchmarkSelector.Kind kind,
			String moid, String version) {
		String key = AppliedBenchmarkTracker.key(kind, moid);
		ComplianceDecisions.Decision d = ComplianceDecisions.decide(sel, kind,
				version, tracker.previous(key), all);
		if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
			pushed.put(key, ComplianceDecisions.versionUnreadableStats());
			return null;
		}
		return d;
	}

	private void noBenchmark(BenchmarkSelector.Kind kind, String moid,
			ComplianceDecisions.Decision d, ComplianceRollup rollup) {
		rollup.recordNoBenchmark(kind);
		pushed.put(AppliedBenchmarkTracker.key(kind, moid),
				ComplianceDecisions.noBenchmarkStats());
		afterPush(kind, moid, d);
	}

	private void scored(BenchmarkSelector.Kind kind, String moid,
			ComplianceDecisions.Decision d, ControlEvaluator.ComplianceResult cr) {
		pushed.put(AppliedBenchmarkTracker.key(kind, moid),
				ComplianceDecisions.complianceStats(cr));
		afterPush(kind, moid, d);
	}

	/** Mirrors ComplianceAdapter.afterPush (cleanup decision + record). */
	private void afterPush(BenchmarkSelector.Kind kind, String moid,
			ComplianceDecisions.Decision d) {
		String key = AppliedBenchmarkTracker.key(kind, moid);
		if (tracker.needsCleanup(key, d.profileName)) {
			boolean first = tracker.firstSight(key);
			String prev = tracker.previous(key);
			Set<String> orphans = ComplianceDecisions.orphanControlIds(kind,
					first || prev == null ? null : all.get(prev), d.profile,
					all.values(), first);
			cleaned.put(key, orphans.size());
		}
		tracker.record(key, d.profileName);
	}

	private String profileName(String key) {
		return tracker.previous(key);
	}

	/** Advanced settings satisfying every advanced_setting control. */
	private static Map<String, String> passingSettings(
			List<BenchmarkProfile.Control> slice) {
		Map<String, String> m = new HashMap<>();
		for (BenchmarkProfile.Control c : slice) {
			if (!"advanced_setting".equals(c.parameterKind)) continue;
			String e = c.expectedValue.trim();
			if (e.equalsIgnoreCase("not present")) continue;
			if (ControlEvaluator.isNonEmptyMode(e)) {
				m.put(c.parameter, "configured");
			} else if (ControlEvaluator.isNotEqualMode(e)) {
				m.put(c.parameter, "/vmfs/volumes/persistent");
			} else {
				m.put(c.parameter, ControlEvaluator.stripUndefinedSuffix(e));
			}
		}
		return m;
	}

	private static ControlEvaluator.ComplianceResult unreadableVim(
			List<BenchmarkProfile.Control> controls, String name) {
		Object u = new Object();
		Map<String, Object> values = new HashMap<>();
		for (BenchmarkProfile.Control c : controls) {
			if (!"vim_property".equals(c.parameterKind)
					&& !"esxcli".equals(c.parameterKind)) continue;
			if (!c.isEvaluable()) continue;
			String p = c.configParameter;
			if (p == null || p.isEmpty() || "N/A".equals(p) || p.contains("\n")) {
				continue;
			}
			values.put(p, u);
		}
		return ControlEvaluator.evaluateVimProperties(controls, values, name, u);
	}

	private static ControlEvaluator.ComplianceResult merge(
			ControlEvaluator.ComplianceResult a,
			ControlEvaluator.ComplianceResult b) {
		int pass = a.passCount + b.passCount;
		int fail = a.failCount + b.failCount;
		int total = a.totalCount + b.totalCount;
		java.util.List<ControlEvaluator.ControlResult> m =
				new java.util.ArrayList<>(a.controlResults);
		m.addAll(b.controlResults);
		return new ControlEvaluator.ComplianceResult(a.hostname, pass, fail,
				total, a.unreadableCount + b.unreadableCount,
				total > 0 ? 100.0 * pass / total : 100.0, m);
	}
}
