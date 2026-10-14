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
 *   <li>#16 (first slice): every per-object loop checks the stop flag
 *       before each object, so Stop Collecting abandons the cycle within
 *       one object, and the abandoned cycle is logged.</li>
 * </ul>
 * Run from the repo root.
 */
public final class Build95TriageTest {

	private static final String P = ComplianceRollup.PREFIX;
	private static final String CA =
			"src/com/vcfcf/adapters/compliance/ComplianceAdapter.java";

	public static void main(String[] args) throws Exception {
		hostListingFailure();
		stopBetweenObjects();
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

	/** #16 first slice. */
	static void stopBetweenObjects() throws Exception {
		boolean[] flag = {false};
		StopCheck sc = new StopCheck(() -> flag[0]);
		int processed = 0;
		String[] objects = {"esx01", "esx02", "esx03", "esx04"};
		try {
			for (String o : objects) {
				sc.check("host " + o);
				processed++;
				if (o.equals("esx02")) flag[0] = true;   // Stop requested
			}
			T.check(false, "a requested stop throws");
		} catch (InterruptedException e) {
			T.check(e.getMessage().contains("before host esx03"),
					"names where it stopped: " + e.getMessage());
		}
		T.eq(2, processed, "stopped within one object of the request");
		T.eq("host esx03", sc.stoppedAt(), "stoppedAt");
		new StopCheck(() -> false).check("x");   // no stop: no throw

		String ca = OverridesTest.readSrc(CA);
		String[][] loops = {
				{"private java.util.Map<String, String> collectHosts(",
						"for (VSphereClient.HostInfo hostInfo : hosts) { "
						+ "stop.check(\"host \" + hostInfo.name);"},
				{"private void collectVms(",
						"for (VSphereClient.VmInfo vm : vms) { "
						+ "stop.check(\"VM \" + vm.name);"},
				{"private void collectDvs(",
						"for (VSphereClient.DvsInfo dvs : switches) { "
						+ "stop.check(\"vDS \" + dvs.name);"},
				{"private void collectDvpg(",
						"for (VSphereClient.DvpgInfo pg : pgs) { "
						+ "stop.check(\"portgroup \" + pg.name);"},
				{"private void collectClusters(",
						"for (VSphereClient.ClusterInfo cluster : clusters) { "
						+ "stop.check(\"cluster \" + cluster.name);"},
				{"private void runShadow(",
						"for (VSphereClient.BulkRow row : rows) { "
						+ "stop.check(\"bulk shadow \""},
				{"private void cleanStaleControls(",
						"i += CLEANUP_BATCH) { stop.check(\"per-control "
						+ "cleanup of \""},
		};
		for (String[] l : loops) {
			String b = OverridesTest.body(ca, l[0]);
			T.check(b.contains(l[1]), l[0] + " checks the stop flag first "
					+ "in its loop");
		}
		// runShadow does not swallow the stop; the cycle logs it.
		OverridesTest.inOrder(OverridesTest.body(ca, "private void runShadow("),
				"runShadow", "catch (InterruptedException e) { throw e; }",
				"catch (Exception e) {");
		OverridesTest.inOrder(OverridesTest.body(ca,
				"private void collectWorld("), "collectWorld",
				"catch (InterruptedException e) {",
				"logWarn(\"ComplianceAdapter cycle abandoned after \"",
				"throw e; }");
		T.check(ca.contains("new StopCheck(() -> isAbortRequested() "
				+ "|| Thread.currentThread().isInterrupted())")
				|| OverridesTest.stripComments(ca).replaceAll("\\s+", " ")
						.contains("new StopCheck(() -> isAbortRequested() "
						+ "|| Thread.currentThread().isInterrupted())"),
				"the flag is the framework stop request or an interrupt");
	}
}
