package com.vcfcf.adapters.compliance;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Build 96, issue #42 (DEF-025): a control retired from an object (guide
 * version change, or no longer applicable) gets Compliant = -1 on later
 * cycles too, not once, so an alert open on the key sees the three
 * non-failing samples it needs to cancel; review W1 caps it at 4 -1 samples
 * per key (the retirement included), counted only once a read-back shows
 * them landed (Codex P2 on PR #57). A key the object never
 * had is still never created, and a lingering 1 outside the benchmark is
 * still left alone. Run from the repo root.
 */
public final class Build96RetiredKeyTest {

	public static void main(String[] args) throws Exception {
		decision();
		cap();
		failedPushDoesNotConsume();
		repeatsEveryCycle();
		repeatsWhenEveryCycleEndsEarly();
		failedPushThroughAdapter();
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
		long ts = 300_000L;
		// Cycle 1: the cleanup read-back retires the key (pending).
		r.beginCycle();
		T.eq(k, r.toPush("obj", k, none, false, null, ts), "the retirement");
		// Cycles 2 to 4: the repeat rides the object push; the same cycle's
		// read-back shows it landed and counts it.
		for (int c = 2; c <= 4; c++) {
			r.beginCycle();
			long pushTs = (ts += 300_000L);
			T.eq(k, r.fold("obj", none, pushTs), "cycle " + c + ": folded");
			java.util.Set<Long> landed = new java.util.HashSet<>();
			for (long x = 300_000L; x <= pushTs; x += 300_000L) landed.add(x);
			Map<String, Set<Long>> tm = new HashMap<>();
			tm.put("k", landed);
			T.check(r.toPush("obj", none, k, false, tm, ts + 1).isEmpty(),
					"cleanup does not push it again");
		}
		T.eq(4, r.confirmed("obj", "k"), "4 samples landed");
		r.beginCycle();
		T.check(r.fold("obj", none, ts += 300_000L).isEmpty(), "capped");
		// A live key (pushed with a value) is never folded.
		RetiredKeyRepeats l = new RetiredKeyRepeats();
		l.beginCycle();
		l.toPush("o", none, k, false, null, 1);
		l.beginCycle();
		T.check(l.fold("o", k, 2).isEmpty(), "live: not folded");
		// Peer review item 6: a read-back with nothing for the object
		// changes nothing.
		T.check(l.toPush("o", none, none, true, null, 3).isEmpty(),
				"empty read");
		T.eq(1, l.size(), "count kept through an empty read");
		// The key leaves the retired set (read back neither 0/1 nor -1).
		T.check(r.toPush("obj", none, none, false, null, 5).isEmpty(),
				"not retired");
		T.eq(0, r.size(), "forgotten");
		T.eq(4, RetiredKeyRepeats.MAX_PUSHES, "the alert needs 3; 4 samples");

		// Review N1-r2: objects that leave inventory are forgotten.
		RetiredKeyRepeats t = new RetiredKeyRepeats();
		t.toPush("HOST|host-1", k, none, false, null, 1);
		t.toPush("HOST|host-2", k, none, false, null, 1);
		t.toPush("VM|vm-1", k, none, false, null, 1);
		T.eq(3, t.size(), "three objects counted");
		t.retain(new TreeSet<>(java.util.Arrays.asList("HOST|host-1")),
				java.util.EnumSet.of(BenchmarkSelector.Kind.VM));
		T.eq(2, t.size(), "host-2 left inventory: forgotten; VM held back: kept");
	}

	/**
	 * Codex P2 on PR #57: a push that fails (the framework logs and
	 * swallows it) does not consume an attempt: it is counted only when a
	 * read-back shows it landed, and a pending push a later cycle's
	 * read-back does not show is dropped.
	 */
	static void failedPushDoesNotConsume() {
		RetiredKeyRepeats r = new RetiredKeyRepeats();
		java.util.Set<String> none = new TreeSet<>();
		java.util.Set<String> k = new TreeSet<>(java.util.Arrays.asList("k"));
		r.beginCycle();
		r.toPush("obj", k, none, false, null, 300000L);          // retirement
		r.beginCycle();
		T.eq(k, r.fold("obj", none, 600000L), "cycle 2: folded");
		// The read-back shows the retirement, not the cycle-2 fold: that
		// push failed (or has not landed yet). One cycle is 300,000 ms.
		r.toPush("obj", none, k, false, times("k", 3000L, 300000L), 750000L);
		T.eq(1, r.confirmed("obj", "k"), "only the retirement counted");
		r.beginCycle();
		T.eq(k, r.fold("obj", none, 900000L), "cycle 3: folded again");
		r.toPush("obj", none, k, false, times("k", 3000L, 300000L, 900000L), 1050000L);
		T.eq(2, r.confirmed("obj", "k"),
				"the cycle-3 push landed and counts; the cycle-2 push never "
				+ "showed and is dropped, uncounted");
		for (int c = 4; c <= 6; c++) {
			r.beginCycle();
			long t = c * 300000L;
			Set<String> f = r.fold("obj", none, t);
			if (c <= 5) {
				T.eq(k, f, "cycle " + c + ": still owed");
				r.toPush("obj", none, k, false, times("k", 300000L, 900000L, t),
						t + 150000L);
			} else {
				T.check(f.isEmpty(), "cycle 6: 4 landed, capped");
			}
		}
		T.eq(4, r.confirmed("obj", "k"), "4 landed in all");
	}

	/** The read-back's sample times for one key. */
	static Map<String, Set<Long>> times(String id, long... ts) {
		Map<String, Set<Long>> m = new HashMap<>();
		Set<Long> set = new java.util.HashSet<>();
		for (long t : ts) set.add(t);
		m.put(id, set);
		return m;
	}

	/**
	 * Codex P2 on PR #57, through the adapter: the push of one cycle fails;
	 * the -1 samples that land on the key still reach 4 (the failed one
	 * does not count), then stop.
	 */
	static void failedPushThroughAdapter() throws Exception {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		final String id = ComplianceDecisions.candidateControlIds(
				BenchmarkSelector.Kind.HOST, all.get("VMware_SCG_9.0"),
				all.values()).iterator().next();
		final String key = "VCF-CF Compliance|" + id + "|Compliant";
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			h.suite.seed("r-host-10", key, 0.0, 1L);
			int landed = 0;
			int attempts = 0;
			for (int cycle = 1; cycle <= 8; cycle++) {
				h.suite.failPushes = cycle == 2;
				int before = h.suite.pushes.size();
				h.cycle();
				if (lastPushed(h, before, key) != null) {
					attempts++;
					if (cycle != 2) landed++;
				}
			}
			h.suite.failPushes = false;
			T.eq(4, landed, "4 -1 samples landed, the failed push not counted");
			T.eq(5, attempts, "one more attempt for the failed one");
		}
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
			// What VCF Ops holds: a lingering 0, then what lands.
			h.suite.seed("r-host-10", key, 0.0, 1L);
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
			// What VCF Ops holds: a lingering 0, then what lands.
			h.suite.seed("r-host-10", key, 0.0, 1L);
			// Cycle 1, a complete cycle: the cleanup retires the key.
			h.cycle();
			T.eq(-1.0, lastPushed(h, 0, key), "cycle 1: retired (push 1)");
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
