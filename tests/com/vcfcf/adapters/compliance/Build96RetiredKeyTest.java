package com.vcfcf.adapters.compliance;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Build 96, issue #42 (DEF-025): a control retired from an object (guide
 * version change, or no longer applicable) gets Compliant = -1 on later
 * cycles too, not once, so an alert open on the key sees the three
 * non-failing samples it needs to cancel; review W1 caps it at 4 -1 pushes
 * per key (the retirement included). A key the object never
 * had is still never created, and a lingering 1 outside the benchmark is
 * still left alone. Run from the repo root.
 */
public final class Build96RetiredKeyTest {

	public static void main(String[] args) throws Exception {
		decision();
		cap();
		repeatsEveryCycle();
		repeatsWhenEveryCycleEndsEarly();
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

	/** Review W1: 4 pushes per key, then none; a new retirement restarts. */
	static void cap() {
		RetiredKeyRepeats r = new RetiredKeyRepeats();
		java.util.Set<String> none = new TreeSet<>();
		java.util.Set<String> k = new TreeSet<>(java.util.Arrays.asList("k"));
		// Cleanup read-back: the retirement is push 1.
		r.beginCycle();
		T.eq(k, r.toPush("obj", k, none, false), "push 1: the retirement");
		// Peer review item 4: the repeats ride the object's own push.
		for (int i = 2; i <= 4; i++) {
			r.beginCycle();
			T.eq(k, r.fold("obj", none), "push " + i + " in the object push");
			T.check(r.toPush("obj", none, k, false).isEmpty(),
					"cleanup does not push it again the same cycle");
		}
		r.beginCycle();
		T.check(r.fold("obj", none).isEmpty(), "push 5: capped");
		T.check(r.toPush("obj", none, k, false).isEmpty(), "cleanup: capped");
		T.check(r.fold("obj2", none).isEmpty(),
				"an object with no known retired key: nothing folded");
		// A held key found by a read-back after a restart, not folded this
		// cycle: the cleanup pushes it, then the object push carries it.
		T.eq(k, r.toPush("obj2", none, k, false), "after a restart: cleanup");
		r.beginCycle();
		T.eq(k, r.fold("obj2", none), "then the object push");
		// A live key (pushed with a value) is never folded.
		r.beginCycle();
		T.check(r.fold("obj2", k).isEmpty(), "live: not folded");
		// Peer review item 6: a read-back with nothing for the object
		// changes nothing.
		T.check(r.toPush("obj2", none, none, true).isEmpty(), "empty read");
		r.beginCycle();
		T.eq(k, r.fold("obj2", none), "count kept through an empty read");
		// The key leaves the retired set (read back neither 0/1 nor -1).
		T.check(r.toPush("obj", none, none, false).isEmpty(), "not retired");
		r.beginCycle();
		T.check(r.fold("obj", none).isEmpty(), "forgotten");
		T.eq(k, r.toPush("obj", k, none, false), "a new retirement afresh");
		T.eq(4, RetiredKeyRepeats.MAX_PUSHES, "the alert needs 3; 4 pushes");

		// Review N1-r2: objects that leave inventory are forgotten, with
		// the same seen set and held-back rule as the benchmark memory.
		RetiredKeyRepeats t = new RetiredKeyRepeats();
		t.toPush("HOST|host-1", k, none, false);
		t.toPush("HOST|host-2", k, none, false);
		t.toPush("VM|vm-1", k, none, false);
		T.eq(3, t.size(), "three objects counted");
		t.retain(new TreeSet<>(java.util.Arrays.asList("HOST|host-1")),
				java.util.EnumSet.of(BenchmarkSelector.Kind.VM));
		T.eq(2, t.size(), "host-2 left inventory: forgotten; VM held back: kept");
	}

	/**
	 * Through the adapter: a host on SCG 9.0 holds a 0 on a control that
	 * only another guide version checks (its version changed). Cycle 1
	 * sets it to -1; cycles 2 to 4 read -1 back and push -1 again; cycles
	 * 5 and 6 push nothing for it (the cap).
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
			for (int cycle = 1; cycle <= 6; cycle++) {
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
				T.eq(cycle <= 4 ? -1.0 : null, pushed, "cycle " + cycle + ": "
						+ id + (cycle <= 4 ? " pushed -1" : " not pushed (cap)"));
				stored[0] = -1.0;   // what VCF Ops now holds
			}
			T.check(h.logged("retired key(s) already at -1 pushed -1 again"),
					"cleanup line counts the repeats");
		}
	}

	/**
	 * Peer review item 4: on an instance where every cycle ends early (the
	 * cleanup at the end of the cycle never runs), the -1 repeats still
	 * reach the key, because they ride the object's own push; and the
	 * cleanup the cycle could not run is carried to the start of the next.
	 */
	static void repeatsWhenEveryCycleEndsEarly() throws Exception {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		final String id = ComplianceDecisions.candidateControlIds(
				BenchmarkSelector.Kind.HOST, all.get("VMware_SCG_9.0"),
				all.values()).iterator().next();
		final String key = "VCF-CF Compliance|" + id + "|Compliant";
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			java.util.concurrent.atomic.AtomicLong now =
					new java.util.concurrent.atomic.AtomicLong(0);
			h.adapter.budgetClock = now::get;
			final double[] stored = {0.0};
			h.suite.answer = p -> {
				if (!p.contains("/stats/latest")) return null;
				return "{\"values\":[{\"resourceId\":\"r-host-10\","
						+ "\"stat-list\":{\"stat\":[{\"statKey\":{\"key\":\""
						+ key + "\"},\"data\":[" + stored[0] + "]}]}}]}";
			};
			// Cycle 1, a complete cycle: the cleanup retires the key.
			h.cycle();
			T.eq(-1.0, lastPushed(h, 0, key), "cycle 1: retired (push 1)");
			stored[0] = -1.0;
			// Every later cycle: the budget runs out on host-10's last read,
			// so host-10 is pushed in full, host-11 is not reached and the
			// end-of-cycle cleanup is skipped.
			int r0 = h.vc.requests.size();
			int n = 0;
			h.cycle();   // measure host-10's calls in a full cycle
			synchronized (h.vc.requests) {
				for (FakeVCenter.Req q : h.vc.requests.subList(r0,
						h.vc.requests.size())) {
					if (q.body.contains("host-10")) n++;
				}
			}
			final int last = n;
			final int[] calls = {0};
			h.override = r -> {
				if (r.body.contains("host-10") && ++calls[0] == last) {
					now.addAndGet(400L * 1_000_000_000L);
				}
				return null;
			};
			int pushes = 0;
			for (int c = 1; c <= 4; c++) {
				calls[0] = 0;
				int before = h.suite.pushes.size();
				h.cycle();
				T.check(h.logged("Stale-control cleanup skipped this cycle"),
						"the end-of-cycle cleanup is skipped");
				if (lastPushed(h, before, key) != null) pushes++;
			}
			// Cycle 1 pushed 1 and the measuring cycle 1 more (2 of 4), so
			// two more ride host-10's push, then the cap.
			T.eq(2, pushes, "the remaining repeats ride the object's push");
			T.check(h.logged("Stale-control cleanup carried from the last cycle"),
					"the skipped cleanup runs at the start of the next cycle");
		}
	}

	static Double lastPushed(AdapterHarness h, int from, String key) {
		Double v = null;
		synchronized (h.suite.pushes) {
			for (FakeSuiteApi.Push p : h.suite.pushes.subList(from,
					h.suite.pushes.size())) {
				if (p.stats != null && p.resourceId.equals("r-host-10")
						&& p.stats.containsKey(key)) {
					v = p.stats.get(key);
				}
			}
		}
		return v;
	}
}
