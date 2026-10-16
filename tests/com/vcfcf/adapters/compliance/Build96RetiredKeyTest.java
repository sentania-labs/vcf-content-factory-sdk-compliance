package com.vcfcf.adapters.compliance;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Build 96, issue #42 (DEF-025): a control retired from an object (guide
 * version change, or no longer applicable) gets Compliant = -1 on every
 * cycle while it stays retired, not once, so an alert open on the key sees
 * the three non-failing samples it needs to cancel. A key the object never
 * had is still never created, and a lingering 1 outside the benchmark is
 * still left alone. Run from the repo root.
 */
public final class Build96RetiredKeyTest {

	public static void main(String[] args) throws Exception {
		decision();
		repeatsEveryCycle();
		System.out.println("Build96RetiredKeyTest: all assertions passed");
	}

	static void decision() {
		ComplianceDecisions.CleanupPlan plan = new ComplianceDecisions.CleanupPlan(
				new TreeSet<>(java.util.Arrays.asList("na.1")),
				new TreeSet<>(java.util.Arrays.asList("old.1", "old.2", "old.3")));
		Map<String, Double> latest = new HashMap<>();
		latest.put("na.1", -1.0);     // not applicable, retired earlier
		latest.put("old.1", -1.0);    // outside the benchmark, retired earlier
		latest.put("old.2", 0.0);     // still failing: retired this cycle
		latest.put("old.3", 1.0);     // lingering 1 outside the benchmark
		latest.put("live.1", -1.0);   // not a candidate: never touched
		T.eq(new TreeSet<>(java.util.Arrays.asList("na.1", "old.1")),
				ComplianceDecisions.heldNotEvaluatedControls(plan, latest),
				"keys already at -1 are pushed -1 again");
		T.eq(new TreeSet<>(java.util.Arrays.asList("old.2")),
				ComplianceDecisions.staleControls(plan, latest),
				"retirement itself unchanged");
		T.check(ComplianceDecisions.heldNotEvaluatedControls(plan, null)
				.isEmpty(), "read failed: nothing");
		T.check(ComplianceDecisions.heldNotEvaluatedControls(plan,
				new HashMap<>()).isEmpty(), "absent key: never created");
	}

	/**
	 * Through the adapter: a host on SCG 9.0 holds a 0 on a control that
	 * only another guide version checks (its version changed). Cycle 1
	 * sets it to -1; cycles 2 and 3 read -1 back and push -1 again.
	 */
	static void repeatsEveryCycle() throws Exception {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		Set<String> retired = ComplianceDecisions.candidateControlIds(
				BenchmarkSelector.Kind.HOST, all.get("VMware_SCG_9.0"),
				all.values());
		T.check(!retired.isEmpty(), "a host control outside SCG 9.0 exists");
		final String id = retired.iterator().next();
		final String key = "VCF-CF Compliance|" + id + "|Compliant";
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			final double[] stored = {0.0};
			h.suite.answer = p -> {
				if (!p.contains("/stats/latest")) return null;
				return "{\"values\":[{\"resourceId\":\"r-host-10\","
						+ "\"stat-list\":{\"stat\":[{\"statKey\":{\"key\":\""
						+ key + "\"},\"data\":[" + stored[0] + "]}]}}]}";
			};
			for (int cycle = 1; cycle <= 3; cycle++) {
				int before = h.suite.pushes.size();
				h.cycle();
				Double pushed = null;
				synchronized (h.suite.pushes) {
					for (FakeSuiteApi.Push p : h.suite.pushes.subList(before,
							h.suite.pushes.size())) {
						if (p.stats != null && p.resourceId.equals("r-host-10")
								&& p.stats.containsKey(key)) {
							pushed = p.stats.get(key);
						}
					}
				}
				T.eq(-1.0, pushed, "cycle " + cycle + ": " + id
						+ " pushed -1");
				stored[0] = -1.0;   // what VCF Ops now holds
			}
			T.check(h.logged("retired key(s) already at -1 pushed -1 again"),
					"cleanup line counts the repeats");
		}
	}
}
