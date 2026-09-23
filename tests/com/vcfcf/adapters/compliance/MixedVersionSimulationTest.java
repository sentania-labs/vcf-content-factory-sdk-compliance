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
 * {@link ComplianceDecisions#candidateControlIds},
 * {@link ComplianceDecisions#staleZeroControls}, {@link LastBenchmarkMemory}),
 * with the real bundled profiles, evaluator and rollup. Only the SOAP reads
 * and the Suite API are simulated: {@code ops} keeps the last value pushed
 * to every key of every object, as VCF Ops does.
 *
 * <p>Cycle 1: vCenter 9.1.1; hosts on ESXi 6.7, 7.0, 8.0 U3, 9.0, 9.1
 * (disconnected: every control unreadable, scores 0) and unmapped 10.0; VMs on the 6.7,
 * 8.0 U3 and 10.0 hosts; a vDS reporting its own 9.0.0 (ignored) and a
 * portgroup. Cycle 2: the 8.0 host was upgraded to 9.0 while one of its
 * 8.0-only controls still reads 0 (an open alert); the 7.0 host's version
 * read fails (reuses 7.0); a new host appears whose version cannot be read.
 * Cycle 3: the latest-value read fails, so nothing is cleaned.
 */
public final class MixedVersionSimulationTest {

	private static final String P = ComplianceRollup.PREFIX;
	private static final String K = "VCF-CF Compliance|";

	private final Map<String, BenchmarkProfile> all;
	private final BenchmarkSelector sel;
	private final LastBenchmarkMemory memory = new LastBenchmarkMemory();
	// Simulated VCF Ops: object -> stat key -> latest value (never forgets).
	private final Map<String, Map<String, Double>> ops = new HashMap<>();
	// This cycle: object -> controls cleaned; objects pushed with a benchmark.
	private final Map<String, Set<String>> cleaned = new HashMap<>();
	private final Map<String, BenchmarkProfile> pending = new LinkedHashMap<>();
	private boolean bulkReadFails;

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
		Map<String, Double> h100 = ops.get("HOST|host-100");
		T.near(1, h100.get(K + "no_benchmark"), "10.0 host no_benchmark");
		T.near(0, h100.get(K + "non_compliant"), "10.0 host not nc");
		T.near(0, h100.get(K + "total_count"), "10.0 host total zeroed");
		T.check(!h100.containsKey(K + "score"), "10.0 host no score");
		T.near(1, ops.get("VM|vm-b").get(K + "no_benchmark"),
				"VM on 10.0 host no_benchmark");
		T.near(1, ops.get("HOST|host-91").get(K + "non_compliant"),
				"disconnected host non-compliant");


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
		T.near(5, r1.toStats().get(P + "Host|scored"),
				"4 read hosts + the disconnected host at 0");
		T.near(0, ops.get("HOST|host-91").get(K + "score"),
				"disconnected host scores 0 (nothing collected)");
		T.near(1, ops.get("HOST|host-91").get(K + "collection_failed"),
				"disconnected host: collection_failed = 1");
		T.near(0, ops.get("HOST|host-90").get(K + "collection_failed"),
				"read host: collection_failed = 0");
		T.check(!r1.toStats().containsKey(P + "Host|scored_stale"),
				"scored_stale retired");

		// Nothing was stale on first sight (v3 keys are new): no key created.
		T.check(cleaned.isEmpty(), "first cycle cleans nothing, creates nothing");
		T.check(!ops.get("HOST|host-91").containsKey(
				ComplianceDecisions.compliantKey("esx.logs-remote")),
				"no key for a control the object never had");

		// ---------------- cycle 2
		// host-80 had an 8.0-only control failing (its alert is open).
		Set<String> only80 = ComplianceDecisions.candidateControlIds(
				BenchmarkSelector.Kind.HOST, all.get("VMware_SCG_9.0"),
				all.values());
		String openAlert = null;
		for (String cid : only80) {
			if (ops.get("HOST|host-80").containsKey(
					ComplianceDecisions.compliantKey(cid))) {
				openAlert = cid;
				break;
			}
		}
		T.check(openAlert != null, "fixture: an 8.0-only control on host-80");
		ops.get("HOST|host-80").put(ComplianceDecisions.compliantKey(openAlert),
				0.0);
		cleaned.clear();
		hosts.put("host-80", "9.0.0");     // upgraded
		hosts.put("host-70", null);        // version read fails
		hosts.put("host-new", null);       // new, version unreadable
		ComplianceRollup r2 = cycle(vc, hosts, vmHost, "host-91");

		T.eq("VMware_SCG_9.0", profileName("HOST|host-80"), "upgraded host");
		// Expected: the seeded open alert, plus host-80's REAL cycle-1 8.0
		// failure when that control id is not in SCG 9.0 (it is now a stale 0
		// outside the benchmark too).
		Set<String> expected = new java.util.TreeSet<>();
		expected.add(openAlert);
		String fail80 = failingControl("VMware_SCG_8.0");
		if (only80.contains(fail80)) expected.add(fail80);
		T.eq(expected, cleaned.get("HOST|host-80"),
				"exactly the stale 0s outside 9.0 flip to -1");
		T.near(-1, ops.get("HOST|host-80").get(
				ComplianceDecisions.compliantKey(openAlert)), "now -1");
		// The live failure inside the new benchmark is untouched (still 0).
		T.near(0, ops.get("HOST|host-80").get(ComplianceDecisions.compliantKey(
				failingControl("VMware_SCG_9.0"))), "in-benchmark 0 untouched");
		T.eq("VMware_SCG_9.0", profileName("VM|vm-a"), "VM follows upgrade");

		// B2: failed version read reuses the last benchmark.
		T.eq("VMware_SCG_7.0", profileName("HOST|host-70"), "7.0 reused");
		// B2: unreadable with no history is non-compliant, not no-benchmark.
		Map<String, Double> hn = ops.get("HOST|host-new");
		T.near(1, hn.get(K + "non_compliant"), "new unreadable host nc");
		T.near(0, hn.get(K + "no_benchmark"), "not no_benchmark");
		T.check(!hn.containsKey(K + "unreadable_count"),
				"unreadable_count not pushed when the version is unreadable");
		T.near(0, hn.get(K + "score"), "version unreadable scores 0");
		T.near(1, hn.get(K + "collection_failed"), "collection_failed = 1");
		T.check(memory.previous("HOST|host-new") == null,
				"unreadable object not remembered");
		T.check(!cleaned.containsKey("HOST|host-new"), "no cleanup");

		Map<String, Double> s2 = r2.toStats();
		T.near(1, s2.get(P + "Benchmark|unknown|objects"), "unknown bucket");
		T.near(1, s2.get(P + "Host|no_benchmark"), "only the 10.0 host");
		T.near(3, s2.get(P + "Host|non_compliant"),
				"9.1 unreadable + new unreadable + 9.0 upgraded (fails)");

		// ---------------- cycle 3: bulk read fails -> nothing changes
		String another = null;
		for (String cid : only80) {
			if (!cid.equals(openAlert) && ops.get("HOST|host-80").containsKey(
					ComplianceDecisions.compliantKey(cid))) {
				another = cid;
				break;
			}
		}
		if (another != null) {
			ops.get("HOST|host-80").put(
					ComplianceDecisions.compliantKey(another), 0.0);
		}
		Map<String, Map<String, Double>> before = deepCopy(ops);
		cleaned.clear();
		bulkReadFails = true;
		cycle(vc, hosts, vmHost, "host-91");
		T.check(cleaned.isEmpty(), "failed bulk read cleans nothing");
		if (another != null) {
			T.near(0, ops.get("HOST|host-80").get(
					ComplianceDecisions.compliantKey(another)),
					"stale 0 kept until a read succeeds");
		}
		T.eq(before.get("HOST|host-80").keySet(),
				ops.get("HOST|host-80").keySet(), "no keys created");
		bulkReadFails = false;

		// ---------------- restart case (build 65, review W1)
		// Collector restart: benchmark memory is gone. host-90's version
		// read now fails, so there is nothing to reuse: the object scores
		// 0, collection_failed = 1 (collection alert), non-compliant, in the
		// unknown bucket, counted as scored 0 in the rollup.
		memory.clear();
		cleaned.clear();
		hosts.put("host-90", null);
		ComplianceRollup r4 = cycle(vc, hosts, vmHost, "host-91");
		Map<String, Double> h90 = ops.get("HOST|host-90");
		T.near(0, h90.get(K + "score"), "after restart: score 0");
		T.near(1, h90.get(K + "collection_failed"), "after restart: failed");
		T.near(1, h90.get(K + "non_compliant"), "after restart: nc");
		T.near(0, h90.get(K + "no_benchmark"), "after restart: not nb");
		Map<String, Double> s4 = r4.toStats();
		T.near(3, s4.get(P + "Benchmark|unknown|objects"),
				"unknown: host-70, host-new, host-90 (no memory after restart)");
		T.check(!cleaned.containsKey("HOST|host-90"), "no cleanup");
	}

	/** The control the 9.0/8.0 host fails in the simulation (lockout). */
	private String failingControl(String profile) {
		for (BenchmarkProfile.Control c : all.get(profile).hostControls()) {
			if ("Security.AccountLockFailures".equals(c.parameter)
					&& BenchmarkSelector.evaluatedFor(
							BenchmarkSelector.Kind.HOST, c)) {
				return c.controlId;
			}
		}
		throw new AssertionError("no lockout control in " + profile);
	}

	private static Map<String, Map<String, Double>> deepCopy(
			Map<String, Map<String, Double>> m) {
		Map<String, Map<String, Double>> out = new HashMap<>();
		for (Map.Entry<String, Map<String, Double>> e : m.entrySet()) {
			out.put(e.getKey(), new HashMap<>(e.getValue()));
		}
		return out;
	}

	/** One simulated collect cycle through the adapter's decision code. */
	private ComplianceRollup cycle(String vcVersion, Map<String, String> hosts,
			Map<String, String> vmHost, String disconnectedHost) {
		ComplianceRollup rollup = new ComplianceRollup();
		pending.clear();
		Map<String, String> hostVersions = new HashMap<>();
		for (Map.Entry<String, String> h : hosts.entrySet()) {
			hostVersions.put(h.getKey(), h.getValue());
			BenchmarkSelector.Kind kind = BenchmarkSelector.Kind.HOST;
			ComplianceDecisions.Decision d = decide(kind, h.getKey(),
					BenchmarkSelector.governingVersion(kind, vcVersion,
							h.getValue()));
			if (d == null) {
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
			memory.record(LastBenchmarkMemory.key(kind, o[1]), d.profileName);
		}
		cleanStale();
		return rollup;
	}

	/**
	 * decide() as the adapter calls it; a VERSION_UNREADABLE outcome is
	 * pushed and returned as null to the caller.
	 */
	private ComplianceDecisions.Decision decide(BenchmarkSelector.Kind kind,
			String moid, String version) {
		String key = LastBenchmarkMemory.key(kind, moid);
		ComplianceDecisions.Decision d = ComplianceDecisions.decide(sel, kind,
				version, memory.previous(key), all);
		if (d.outcome == ComplianceDecisions.Outcome.VERSION_UNREADABLE) {
			push(key, ComplianceDecisions.versionUnreadableStats());
			return null;
		}
		return d;
	}

	private void push(String key, Map<String, Double> stats) {
		ops.computeIfAbsent(key, k -> new HashMap<>()).putAll(stats);
	}

	private void noBenchmark(BenchmarkSelector.Kind kind, String moid,
			ComplianceDecisions.Decision d, ComplianceRollup rollup) {
		rollup.recordNoBenchmark(kind);
		push(LastBenchmarkMemory.key(kind, moid),
				ComplianceDecisions.noBenchmarkStats());
		afterPush(kind, moid, d);
	}

	private void scored(BenchmarkSelector.Kind kind, String moid,
			ComplianceDecisions.Decision d, ControlEvaluator.ComplianceResult cr) {
		push(LastBenchmarkMemory.key(kind, moid),
				ComplianceDecisions.complianceStats(cr));
		afterPush(kind, moid, d);
	}

	/** Mirrors ComplianceAdapter.afterPush (remember + queue). */
	private void afterPush(BenchmarkSelector.Kind kind, String moid,
			ComplianceDecisions.Decision d) {
		String key = LastBenchmarkMemory.key(kind, moid);
		memory.record(key, d.profileName);
		pending.put(key, d.profile);
	}

	/**
	 * Mirrors ComplianceAdapter.cleanStaleControls: candidates per object,
	 * a "bulk read" of their latest values from the simulated VCF Ops
	 * (only keys that exist are returned), -1 only for stale 0s.
	 */
	private void cleanStale() {
		for (Map.Entry<String, BenchmarkProfile> e : pending.entrySet()) {
			BenchmarkSelector.Kind kind = BenchmarkSelector.Kind.valueOf(
					e.getKey().substring(0, e.getKey().indexOf('|')));
			Set<String> cand = ComplianceDecisions.candidateControlIds(kind,
					e.getValue(), all.values());
			Map<String, Double> latest = null;
			if (!bulkReadFails) {
				latest = new HashMap<>();
				Map<String, Double> store = ops.getOrDefault(e.getKey(),
						new HashMap<>());
				for (String cid : cand) {
					Double v = store.get(ComplianceDecisions.compliantKey(cid));
					if (v != null) latest.put(cid, v);
				}
			}
			Set<String> stale = ComplianceDecisions.staleZeroControls(cand,
					latest);
			if (!stale.isEmpty()) {
				push(e.getKey(), ComplianceDecisions.orphanStats(stale));
				cleaned.put(e.getKey(), stale);
			}
		}
	}

	private String profileName(String key) {
		return memory.previous(key);
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
		int unreadable = a.unreadableCount + b.unreadableCount;
		return new ControlEvaluator.ComplianceResult(a.hostname, pass, fail,
				total, unreadable, ControlEvaluator.score(pass, fail, unreadable),
				m);
	}
}
