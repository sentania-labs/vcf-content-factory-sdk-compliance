package com.vcfcf.adapters.compliance;

import java.util.Map;

/**
 * Build 96 (issue #27): the adapter's own collection cycle (collectWorld,
 * ComplianceAdapter compiled against tests/stubs) run against a fake
 * vCenter and a fake Suite API ({@link AdapterHarness}). Run from the repo
 * root.
 */
public final class Build96OrchestrationTest {

	private static final String P = ComplianceRollup.PREFIX;

	public static void main(String[] args) throws Exception {
		normalCycle();
		System.out.println("Build96OrchestrationTest: all assertions passed");
	}

	/** A complete cycle: hosts scored and pushed, the rollup complete. */
	static void normalCycle() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			h.cycle();
			Map<String, Double> r = h.lastRollup();
			T.check(r != null, "rollup pushed to the vCenter object");
			T.eq(0.0, r.get(ComplianceRollup.INCOMPLETE_KEY), "complete cycle");
			T.eq(2.0, r.get(P + "Host|scored"), "both hosts scored");
			T.check(r.containsKey(P + "All|scored"), "All pushed");
			T.check(!h.suite.statsFor("r-host-10").isEmpty(),
					"host-10 pushed to its VCF Ops resource");
			T.check(h.logged("ComplianceAdapter collection complete"),
					"completion line");
		}
	}
}
