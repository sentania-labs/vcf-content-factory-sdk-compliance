package com.vcfcf.adapters.compliance;

import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Build 104 (issue #17, the second box): a cycle's Suite API pushes go out
 * as ONE batched push (buildkit 1.0.24 {@code pushBatch}: properties for
 * every resource, then stats), not two per-id calls per object. Checks:
 * the batch carries every object's properties and stats, merged per
 * resource exactly as the per-object pushes were; one timestamp per cycle;
 * a non-clean result logs one WARN with the counts and the reason and never
 * throws or aborts the cycle; a thrown push is the same; an empty cycle
 * sends nothing and logs nothing; outside a cycle a push goes at once.
 * Run from the repo root.
 */
public final class Build104BatchPushTest {

	public static void main(String[] args) throws Exception {
		queuedThenOneBatch();
		emptyCycleSendsNothing();
		outsideCycleSendsAtOnce();
		notCleanWarnsAndDoesNotThrow();
		thrownPushWarnsAndDoesNotThrow();
		stoppedSkipsLaterTimestamps();
		cycleIsOneBatch();
		cycleSurvivesNotCleanBatch();
		System.out.println("Build104BatchPushTest: all assertions passed");
	}

	private static ComplianceStitcher logging(FakeSuiteApi s,
			List<String> lines) {
		return Build96StitcherTest.logging(s, lines);
	}

	private static Map<String, String> props(String... kv) {
		Map<String, String> m = new LinkedHashMap<>();
		for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
		return m;
	}

	private static Map<String, Double> stats(Object... kv) {
		Map<String, Double> m = new LinkedHashMap<>();
		for (int i = 0; i + 1 < kv.length; i += 2) {
			m.put((String) kv[i], ((Number) kv[i + 1]).doubleValue());
		}
		return m;
	}

	/** Pushes in a cycle are queued and go out as one batch, merged. */
	static void queuedThenOneBatch() {
		FakeSuiteApi s = new FakeSuiteApi();
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.beginPushCycle(1000L);
		long ts = st.pushTimestamp();
		T.eq(1000L, ts, "the cycle timestamp");
		st.pushProperties("r-1", props("a|x", "1", "a|y", "2"), ts);
		st.pushStats("r-1", stats("a|s", 1), ts);
		st.pushProperties("r-2", props("a|x", "3"), ts);
		st.pushStats("r-2", stats("a|s", 0), ts);
		// A second push to r-1 this cycle (the cleanup's): merged in.
		st.pushProperties("r-1", props("b|x", "4"), ts);
		st.pushStats("r-1", stats("b|s", -1), ts);
		st.pushProperties("r-3", Collections.<String, String>emptyMap(), ts);
		T.eq(0, s.batches.size(), "nothing sent while the cycle runs");

		ComplianceStitcher.BatchOutcome o = st.flushPushes();
		T.eq(1, s.batches.size(), "one batched push");
		FakeSuiteApi.Batch b = s.batches.get(0);
		T.eq(1000L, b.ts, "batch timestamp");
		T.eq(props("a|x", "1", "a|y", "2", "b|x", "4"), b.props.get("r-1"),
				"r-1 properties, both pushes");
		T.eq(props("a|x", "3"), b.props.get("r-2"), "r-2 properties");
		T.eq(stats("a|s", 1, "b|s", -1), b.stats.get("r-1"), "r-1 stats");
		T.eq(stats("a|s", 0), b.stats.get("r-2"), "r-2 stats");
		T.check(!b.props.containsKey("r-3"), "an empty map is not sent");
		T.eq(2, b.props.size(), "two resources with properties");
		T.check(o.isClean(), "clean result");
		T.eq(2, o.requests(), "one properties and one stats request");
		T.eq(1, lines.size(), "one summary line: " + lines);
		T.check(lines.get(0).startsWith("Suite API push: 2 resource(s) "
				+ "with properties and 2 with stats, 7 value(s), in 2 "
				+ "request(s)"), lines.get(0));
		T.check(st.flushPushes() == ComplianceStitcher.BatchOutcome.NONE,
				"a second flush has nothing to send");
		T.eq(1, s.batches.size(), "still one batch");
		st.endPushCycle();
	}

	/** An empty cycle sends nothing and logs nothing. */
	static void emptyCycleSendsNothing() {
		FakeSuiteApi s = new FakeSuiteApi();
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.beginPushCycle(5L);
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.eq(0, s.batches.size(), "no request");
		T.eq(0, o.requests(), "no request counted");
		T.check(lines.isEmpty(), "nothing logged: " + lines);
	}

	/** With no cycle open a push goes out at once, as a one-entry batch. */
	static void outsideCycleSendsAtOnce() {
		FakeSuiteApi s = new FakeSuiteApi();
		ComplianceStitcher st = logging(s, new ArrayList<String>());
		st.pushStats("r-1", stats("a|s", 2), 77L);
		T.eq(1, s.batches.size(), "sent at once");
		T.eq(stats("a|s", 2), s.batches.get(0).stats.get("r-1"), "the stat");
		T.eq(77L, s.batches.get(0).ts, "the caller's timestamp");
		T.check(s.batches.get(0).props.isEmpty(), "no properties");
	}

	/** A non-clean result: one WARN with counts and reason, no throw. */
	static void notCleanWarnsAndDoesNotThrow() {
		FakeSuiteApi s = new FakeSuiteApi();
		s.batchAnswer = new ComplianceStitcher.BatchOutcome(2, 0, 1, 0, 2, 0,
				true);
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.beginPushCycle(9L);
		st.pushProperties("r-1", props("a|x", "1"), 9L);
		st.pushStats("r-1", stats("a|s", 1), 9L);
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.check(!o.isClean(), "not clean");
		T.eq(1, lines.size(), "one line: " + lines);
		String w = lines.get(0);
		T.check(w.startsWith("WARN Suite API push NOT clean: 1 resource(s) "
				+ "with properties and 1 with stats"), w);
		T.check(w.contains("batchesFailed=1") && w.contains("skipped=2")
				&& w.contains("stopped=true"), "counts: " + w);
		T.check(w.contains("the call stopped early"), "reason: " + w);
		T.check(w.contains("1 batch request(s) failed"), "failed: " + w);
		T.check(w.contains("keeps its last value"), "consequence: " + w);
		// A drop alone is also not clean and says why.
		String d = ComplianceStitcher.pushSummary(
				new ComplianceStitcher.BatchOutcome(1, 1, 0, 0, 0, 3, false),
				1, 0, 4, 1, 0, null);
		T.check(d.contains("NOT clean") && d.contains("3 value(s) dropped"),
				d);
	}

	/** A push that throws (a drift or a fake) is a WARN, not a throw. */
	static void thrownPushWarnsAndDoesNotThrow() {
		FakeSuiteApi s = new FakeSuiteApi();
		s.batchThrows = new IllegalStateException("boom");
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.beginPushCycle(9L);
		st.pushStats("r-1", stats("a|s", 1), 9L);
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.check(!o.isClean() && o.stopped, "stopped");
		T.eq(1, o.skipped, "the entry counted not delivered");
		T.eq(1, lines.size(), "one line: " + lines);
		T.check(lines.get(0).contains("the push threw "
				+ "IllegalStateException: boom"), lines.get(0));
	}

	/**
	 * Two timestamps queued (a push stamped by its caller): a stopped call
	 * on the first sends nothing more, and the rest counts not delivered.
	 */
	static void stoppedSkipsLaterTimestamps() {
		FakeSuiteApi s = new FakeSuiteApi();
		s.batchAnswer = new ComplianceStitcher.BatchOutcome(0, 0, 1, 0, 1, 0,
				true);
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.beginPushCycle(10L);
		st.pushStats("r-1", stats("a|s", 1), 10L);
		st.pushStats("r-2", stats("a|s", 1), 20L);
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.eq(1, s.batches.size(), "one request to a failing server");
		T.eq(2, o.skipped, "both entries not delivered");
		T.check(lines.get(0).contains("(2 timestamps)"), lines.get(0));
	}

	/**
	 * The real cycle (AdapterHarness, 3 hosts and 4 VMs): one batched push
	 * at one timestamp carrying properties and stats for every host, every
	 * VM and the vCenter object, with the same values as the records the
	 * fake keeps per resource.
	 */
	static void cycleIsOneBatch() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02", "host-12", "esx03")) {
			h.vm("vm-1", "app01", "host-10").vm("vm-2", "app02", "host-10")
					.vm("vm-3", "app03", "host-11")
					.vm("vm-4", "app04", "host-12");
			long before = System.currentTimeMillis();
			h.cycle();
			T.eq(1, h.suite.batches.size(), "one batched push per cycle");
			FakeSuiteApi.Batch b = h.suite.batches.get(0);
			T.check(b.ts >= before && b.ts <= System.currentTimeMillis(),
					"stamped with the cycle start");
			Set<String> want = new LinkedHashSet<>();
			for (String m : h.hosts.keySet()) want.add("r-" + m);
			for (String m : h.vms.keySet()) want.add("r-" + m);
			for (String rid : want) {
				Map<String, String> p = b.props.get(rid);
				T.check(p != null && !p.isEmpty(), rid + " has properties");
				T.check(p.containsKey(ComplianceDecisions.K
						+ "profile_name"), rid + " profile_name: "
						+ p.keySet());
				Map<String, Double> st = b.stats.get(rid);
				T.check(st != null && st.containsKey(ComplianceDecisions.K
						+ "score"), rid + " score: "
						+ (st == null ? null : st.keySet()));
			}
			T.check(b.stats.containsKey(AdapterHarness.VC_RESOURCE),
					"the vCenter rollup rides the batch");
			T.check(b.stats.get(AdapterHarness.VC_RESOURCE).containsKey(
					ComplianceRollup.INCOMPLETE_KEY), "rollup keys");
			Set<String> sent = new LinkedHashSet<>(b.props.keySet());
			sent.addAll(b.stats.keySet());
			Set<String> extra = new LinkedHashSet<>(sent);
			extra.removeAll(want);
			extra.remove(AdapterHarness.VC_RESOURCE);
			T.check(extra.isEmpty(), "no unknown resource: " + extra);
			T.check(h.logged("Suite API calls"), "summary line written");
		}
	}

	/** A non-clean batch never fails the cycle; the next cycle pushes again. */
	static void cycleSurvivesNotCleanBatch() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			List<String> lines = Collections.synchronizedList(
					new ArrayList<String>());
			ComplianceStitcher st = logging(h.suite, lines);
			Field f = ComplianceAdapter.class.getDeclaredField("configured");
			f.setAccessible(true);
			f.set(h.adapter, new Configured<SuiteApiStitcher,
					ComplianceStitcher>(h.holder.account, h.client,
					new BenchmarkLoader(), null, st, false));
			h.suite.batchAnswer = new ComplianceStitcher.BatchOutcome(0, 0,
					1, 0, 2, 0, true);
			h.cycle();   // must not throw
			T.check(h.logged("ComplianceAdapter collection complete"),
					"the cycle completed");
			String w = Build96StitcherTest.line(lines,
					"Suite API push NOT clean");
			T.check(w != null && w.startsWith("WARN "), "one WARN: " + lines);
			int warns = 0;
			for (String l : lines) {
				if (l.contains("Suite API push")) warns++;
			}
			T.eq(1, warns, "one summary line per cycle: " + lines);
			h.suite.batchAnswer = null;
			int n = h.suite.batches.size();
			h.cycle();
			T.eq(n + 1, h.suite.batches.size(), "the next cycle pushes");
			String info = Build96StitcherTest.line(lines, "Suite API push: ");
			T.check(info != null, "clean INFO next cycle: " + lines);
			T.check(!info.contains("replaced"), "no key pushed twice to the "
					+ "same resource in a cycle: " + info);
		}
	}
}
