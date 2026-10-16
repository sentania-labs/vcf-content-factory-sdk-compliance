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
		hostListingFailure();
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

	/**
	 * Issue #18 (fixed in build 95; build 96 runs it through the adapter's
	 * own cycle): the vCenter host listing faults. The cycle does not fail:
	 * one WARN, the Host kind held back with All and Benchmark
	 * (Rollup|incomplete = 1), the vCenter still collected and the rollup
	 * still pushed, and the next cycle, with the listing back, is complete.
	 */
	static void hostListingFailure() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			h.cycle();
			T.eq(2.0, h.lastRollup().get(P + "Host|scored"), "cycle 1 hosts");

			h.override = r -> {
				String[] o = FakeVCenter.obj(r.body);
				if (o != null && "ContainerView".equals(o[0])
						&& "HostSystem".equals(FakeVCenter.tag(r.body, "type"))) {
					return FakeVCenter.fault("SystemError",
							"A general system error occurred");
				}
				return null;
			};
			int vcPushesBefore = h.suite.statsFor(AdapterHarness.VC_RESOURCE)
					.size();
			h.cycle();   // must not throw
			Map<String, Double> r2 = h.lastRollup();
			T.eq(1.0, r2.get(ComplianceRollup.INCOMPLETE_KEY),
					"listing failed: incomplete = 1");
			T.check(!r2.containsKey(P + "Host|scored"),
					"Host keys held back");
			T.check(!r2.containsKey(P + "All|scored"), "All held back");
			T.check(r2.containsKey(P + "vCenter|scored"),
					"the vCenter kind is still collected and pushed");
			T.check(vcPushesBefore > 0, "the vCenter object was pushed");
			T.check(h.logged("Failed to enumerate hosts"),
					"one WARN names the failed listing");
			T.check(h.logged("ComplianceAdapter collection complete"),
					"the cycle completed");

			h.override = null;
			h.cycle();
			T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
					"listing back: complete again");
			T.eq(2.0, h.lastRollup().get(P + "Host|scored"),
					"both hosts scored again");
		}
	}
}
