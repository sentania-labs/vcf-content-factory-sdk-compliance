package com.vcfcf.adapters.compliance;

import java.util.Map;

/**
 * Build 103 (PR #69 Codex P1): a resume cursor on the LAST object of a kind
 * (left there when that object was cut by the cycle budget twice and the
 * walk stepped past it) makes the next cycle's walk of the kind empty while
 * the inventory is not. The vDS, portgroup and cluster collectors read the
 * vim type from the trimmed list ({@code list.get(0)}) and threw
 * IndexOutOfBoundsException before {@code walk.finish()} could clear the
 * cursor, so every later cycle failed the same way. The empty walk must
 * reach finish(): the cursor cleared, the carried share added, the kind
 * pushed, and the next cycle a full pass. Host and VM (fixed types) are
 * checked the same way. Run from the repo root.
 */
public final class Build103EmptyResumeTest {

	private static final String P = ComplianceRollup.PREFIX;

	public static void main(String[] args) throws Exception {
		vim(BenchmarkSelector.Kind.VDS, "VmwareDistributedVirtualSwitch",
				"dvs-1", "dvs-2");
		vim(BenchmarkSelector.Kind.PORTGROUP, "DistributedVirtualPortgroup",
				"dvportgroup-1", "dvportgroup-2");
		vim(BenchmarkSelector.Kind.CLUSTER, "ClusterComputeResource",
				"domain-c1", "domain-c2");
		hosts();
		vms();
		System.out.println("Build103EmptyResumeTest: all assertions passed");
	}

	static void vim(BenchmarkSelector.Kind kind, String type, String first,
			String last) throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			h.vim(type, first, "a-" + first).vim(type, last, "b-" + last);
			emptyTail(h, kind, last);
		}
	}

	static void hosts() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			emptyTail(h, BenchmarkSelector.Kind.HOST, "host-11");
		}
	}

	static void vms() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			h.vm("vm-1", "app01", "host-10").vm("vm-2", "app02", "host-10");
			emptyTail(h, BenchmarkSelector.Kind.VM, "vm-2");
		}
	}

	/**
	 * A full cycle, then the cursor put after {@code lastMoid} (the end of
	 * the kind's MOID order) with the round starting at {@code kind}, as
	 * a cut-twice on the last object leaves it. The next cycle must run
	 * and clear it, and the one after is a normal full pass.
	 */
	private static void emptyTail(AdapterHarness h,
			BenchmarkSelector.Kind kind, String lastMoid) throws Exception {
		String what = kind.rollupName + ": ";
		h.cycle();
		T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
				what + "cycle 1 complete");
		Double scored = h.lastRollup().get(P + kind.rollupName + "|scored");

		h.holder.resume.stoppedAfter(kind, lastMoid);
		h.holder.resume.startAt(kind);
		T.eq(lastMoid, h.holder.resume.cursor(kind), what + "cursor set");

		h.cycle();   // threw IndexOutOfBoundsException before this fix
		Map<String, Double> r2 = h.lastRollup();
		T.check(r2 != null, what + "cycle 2 pushed a rollup");
		T.eq(null, h.holder.resume.cursor(kind),
				what + "the empty walk reached finish(): cursor cleared");
		T.eq(0.0, r2.get(ComplianceRollup.INCOMPLETE_KEY),
				what + "cycle 2 complete");
		T.check(r2.containsKey(P + kind.rollupName + "|scored"),
				what + "the kind is pushed, not held back");
		T.check(!h.logged("IndexOutOfBounds"), what + "no index error");

		int before = h.suite.pushes.size();
		h.cycle();
		T.eq(0.0, h.lastRollup().get(ComplianceRollup.INCOMPLETE_KEY),
				what + "cycle 3 complete");
		T.eq(scored, h.lastRollup().get(P + kind.rollupName + "|scored"),
				what + "cycle 3 is a full pass again");
		T.check(pushedTo(h, before, "r-" + lastMoid),
				what + "cycle 3 reads the last object again");
	}

	private static boolean pushedTo(AdapterHarness h, int from, String id) {
		synchronized (h.suite.pushes) {
			for (FakeSuiteApi.Push p : h.suite.pushes.subList(from,
					h.suite.pushes.size())) {
				if (p.resourceId.equals(id)) return true;
			}
		}
		return false;
	}
}
