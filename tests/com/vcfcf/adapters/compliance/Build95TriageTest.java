package com.vcfcf.adapters.compliance;

import java.util.Map;

/**
 * Build 95, open-issue triage items. The adapter orchestration needs the
 * SDK, so its wiring is pinned from source (same approach as
 * ComplianceDecisionsTest), and the behaviour it relies on is tested on the
 * SDK-free classes.
 *
 * <ul>
 *   <li>#18: a failed host listing holds the Host kind back (with All and
 *       Benchmark), sets Rollup|incomplete = 1 and lets the other kinds be
 *       collected, instead of failing the cycle with no signal.</li>
 * </ul>
 * Run from the repo root.
 */
public final class Build95TriageTest {

	private static final String P = ComplianceRollup.PREFIX;
	private static final String CA =
			"src/com/vcfcf/adapters/compliance/ComplianceAdapter.java";

	public static void main(String[] args) throws Exception {
		hostListingFailure();
		System.out.println("Build95TriageTest: all assertions passed");
	}

	/** #18. */
	static void hostListingFailure() {
		String ca = OverridesTest.readSrc(CA);
		String hosts = OverridesTest.body(ca,
				"private java.util.Map<String, String> collectHosts(");
		OverridesTest.inOrder(hosts, "collectHosts",
				"try (CycleMetrics.Scope ph = phase(CycleMetrics.Phase."
						+ "INVENTORY)) { hosts = vsphere.getHosts(); }",
				"catch (Exception e) {",
				"logWarn(\"Failed to enumerate hosts: \"",
				"rollup.markIncomplete(BenchmarkSelector.Kind.HOST);",
				"return hostVersions; }");
		// The cycle still runs every other kind after collectHosts returns.
		OverridesTest.inOrder(OverridesTest.body(ca,
				"private void collectWorldCycle("), "collectWorldCycle",
				"hostVersions = collectHosts(selector, rollup, cs, seen);",
				"collectVms(selector, hostVersions, rollup, cs, seen);",
				"vcEntry = collectVCenter(selector, vcVersion, rollup, cs, seen);",
				"collectDvs(", "collectDvpg(", "collectClusters(",
				"pushRollup(vcEntry, rollup);");

		// What the rollup then pushes: Host, All and Benchmark held back,
		// the other kinds pushed, incomplete = 1.
		ComplianceRollup r = new ComplianceRollup();
		r.markIncomplete(BenchmarkSelector.Kind.HOST);
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19, 4, 0,
				ControlEvaluator.score(15, 4, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.VCENTER, "SCG_9.1", 10, 5, 0,
				ControlEvaluator.score(5, 5, 0));
		Map<String, Double> s = r.toStats();
		T.near(1, s.get(ComplianceRollup.INCOMPLETE_KEY), "incomplete = 1");
		for (String k : new String[] {"scored", "non_compliant",
				"controls_evaluated", "pass_rate", "unmatched"}) {
			T.check(!s.containsKey(P + "Host|" + k), "Host|" + k + " held back");
			T.check(!s.containsKey(P + "All|" + k), "All|" + k + " held back");
		}
		T.check(!s.containsKey(P + "Benchmark|SCG_9.1|objects"),
				"Benchmark held back");
		T.near(1, s.get(P + "VM|scored"), "VMs still collected");
		T.near(50, s.get(P + "vCenter|pass_rate"), "vCenter still collected");

		// VMs read their host's version on demand when the host map is
		// empty (the host listing failed).
		String[] asked = {null};
		String v = ComplianceDecisions.resolveVmHostVersion("host-7",
				new java.util.HashMap<>(), moid -> {
					asked[0] = moid;
					return "9.0.1";
				});
		T.eq("host-7", asked[0], "host version read on demand");
		T.eq("9.0.1", v, "VM governed by the on-demand version");
	}
}
