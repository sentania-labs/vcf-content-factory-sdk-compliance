package com.vcfcf.adapters.compliance;

import com.vcfcf.adapter.stitch.SuiteApiBatchResult;
import com.vcfcf.adapter.stitch.SuiteApiStitcher;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Build 104 (issue #17, the second box): a cycle's Suite API pushes go out
 * in batches (buildkit 1.0.24 {@code pushStatsBatch} then
 * {@code pushPropertiesBatch}), not two per-id calls per object. Checks:
 * every object's properties and stats are carried, merged per resource;
 * stats go first, so a failed properties call never loses a score or a
 * not-collected flag (review W1); the queue is sent inside the walk at a
 * size threshold, so it stays bounded and counts against the budget
 * (review W2/W3); Stop Collecting stops a flush and drops the queue
 * (review W2); the not-reached marker is delivered (review W4); a
 * non-clean result logs one WARN and never throws or aborts the cycle; an
 * empty cycle sends nothing; the adapter's result mapping and the stub's
 * default batch run (review N4). Run from the repo root.
 */
public final class Build104BatchPushTest {

	private static final String K = ComplianceDecisions.K;

	public static void main(String[] args) throws Exception {
		queuedThenStatsFirst();
		emptyCycleSendsNothing();
		outsideCycleSendsAtOnce();
		notCleanWarnsAndDoesNotThrow();
		stoppedPropertiesKeepsStats();
		stoppedStatsSendsNoProperties();
		thrownPushWarnsAndDoesNotThrow();
		thresholdFlushInWalk();
		byteThresholdFlush();
		stopSkipsFlushAndDropsQueue();
		stopBetweenHalves();
		slicesAreOneRequestEach();
		stopAfterFirstSlice();
		budgetDefersInWalkSlices();
		cycleIsOnePushAtOneTimestamp();
		cycleSurvivesNotCleanBatch();
		notReachedMarkerDelivered();
		staleCachedVcIdNotUsed();
		stopMidWalkSendsNothingMore();
		adapterMappingAndStubDefault();
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

	/** Queued, merged per resource, sent stats first then properties. */
	static void queuedThenStatsFirst() {
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
		T.eq(0, s.batches.size(), "nothing sent below the threshold");
		T.eq(4, st.queuedEntries(), "four resource entries queued");

		ComplianceStitcher.BatchOutcome o = st.flushPushes();
		T.eq(2, s.batches.size(), "one stats call, one properties call");
		FakeSuiteApi.Batch first = s.batches.get(0);
		FakeSuiteApi.Batch second = s.batches.get(1);
		T.check(first.isStats() && first.props.isEmpty(), "stats first (W1)");
		T.check(!second.isStats(), "properties second");
		T.eq(1000L, first.ts, "stats timestamp");
		T.eq(1000L, second.ts, "properties timestamp");
		T.eq(props("a|x", "1", "a|y", "2", "b|x", "4"), second.props.get("r-1"),
				"r-1 properties, both pushes");
		T.eq(props("a|x", "3"), second.props.get("r-2"), "r-2 properties");
		T.eq(stats("a|s", 1, "b|s", -1), first.stats.get("r-1"), "r-1 stats");
		T.eq(stats("a|s", 0), first.stats.get("r-2"), "r-2 stats");
		T.check(!second.props.containsKey("r-3"), "an empty map is not sent");
		T.check(o.isClean(), "clean result");
		T.eq(2, o.requests(), "two requests");
		T.eq(1, lines.size(), "one summary line: " + lines);
		T.check(lines.get(0).startsWith("Suite API push: 2 resource(s) "
				+ "with stats and 2 with properties, 7 value(s), in 2 "
				+ "request(s)"), lines.get(0));
		T.eq(0, st.flushPushes().requests(), "a second flush sends nothing");
		T.eq(2, s.batches.size(), "still two calls");
		T.eq(1, lines.size(), "and logs nothing");
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
		st.beginPushCycle(6L);
		st.abandonPushCycle("stopped");
		T.check(lines.isEmpty(), "an empty abandon logs nothing: " + lines);
	}

	/** No cycle open: sent at once, a clean summary at DEBUG only (N5). */
	static void outsideCycleSendsAtOnce() {
		FakeSuiteApi s = new FakeSuiteApi();
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.pushStats("r-1", stats("a|s", 2), 77L);
		T.eq(1, s.batches.size(), "sent at once");
		T.eq(stats("a|s", 2), s.batches.get(0).stats.get("r-1"), "the stat");
		T.eq(77L, s.batches.get(0).ts, "the caller's timestamp");
		T.check(lines.isEmpty(), "no INFO per push (N5): " + lines);
		s.batchAnswer = new ComplianceStitcher.BatchOutcome(0, 0, 1, 0, 1, 0,
				true);
		st.pushProperties("r-1", props("a|x", "1"), 78L);
		T.eq(1, lines.size(), "a failure still WARNs: " + lines);
		T.check(lines.get(0).startsWith("WARN Suite API push NOT clean"),
				lines.get(0));
	}

	/** A non-clean result: one WARN with counts and reason, no throw. */
	static void notCleanWarnsAndDoesNotThrow() {
		FakeSuiteApi s = new FakeSuiteApi();
		s.batchAnswer = new ComplianceStitcher.BatchOutcome(1, 0, 1, 0, 1, 0,
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
				+ "with stats and 1 with properties"), w);
		T.check(w.contains("batchesFailed=1") && w.contains("stopped=true"),
				"counts: " + w);
		T.check(w.contains("skipped=2"), "the properties entry counted not "
				+ "delivered too: " + w);
		T.check(w.contains("the call stopped early"), "reason: " + w);
		T.check(w.contains("1 batch request(s) failed"), "failed: " + w);
		T.check(w.contains("keeps its last value"), "consequence: " + w);
		String d = ComplianceStitcher.pushSummary(
				new ComplianceStitcher.BatchOutcome(1, 1, 0, 0, 0, 3, false),
				1, 0, 4, 1, 0, null);
		T.check(d.contains("NOT clean") && d.contains("3 value(s) dropped"),
				d);
	}

	/**
	 * Review W1: the properties call stops (a 5xx in the big half). The
	 * stats went first and landed: score, has_unreadable and the vCenter
	 * Rollup|incomplete are current.
	 */
	static void stoppedPropertiesKeepsStats() {
		FakeSuiteApi s = new FakeSuiteApi();
		s.propsAnswer = new ComplianceStitcher.BatchOutcome(1, 0, 1, 0, 1, 0,
				true);
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.beginPushCycle(11L);
		st.pushProperties("r-vc", props(K + "x", "big"), 11L);
		st.pushStats("r-vc", stats(ComplianceRollup.INCOMPLETE_KEY, 1), 11L);
		st.pushStats("r-1", stats(K + "score", 80, K + "has_unreadable", 1),
				11L);
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.check(!o.isClean(), "not clean");
		T.near(1.0, s.stored("r-vc", ComplianceRollup.INCOMPLETE_KEY),
				"Rollup|incomplete landed");
		T.near(80.0, s.stored("r-1", K + "score"), "score landed");
		T.near(1.0, s.stored("r-1", K + "has_unreadable"),
				"has_unreadable landed");
	}

	/** A stopped stats call sends nothing more (one request to a failing server). */
	static void stoppedStatsSendsNoProperties() {
		FakeSuiteApi s = new FakeSuiteApi();
		s.batchAnswer = new ComplianceStitcher.BatchOutcome(0, 0, 1, 0, 1, 0,
				true);
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.beginPushCycle(10L);
		st.pushStats("r-1", stats("a|s", 1), 10L);
		st.pushProperties("r-1", props("a|x", "1"), 10L);
		st.pushStats("r-2", stats("a|s", 1), 20L);
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.eq(1, s.batches.size(), "one request to a failing server");
		T.eq(3, o.skipped, "every entry not delivered");
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
	 * Review W2/W3: the queue is sent inside the walk when it reaches the
	 * entry threshold, so it never holds the whole cycle; one summary line
	 * still covers the cycle.
	 */
	static void thresholdFlushInWalk() {
		FakeSuiteApi s = new FakeSuiteApi();
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.setFlushThresholds(4, Long.MAX_VALUE);
		st.beginPushCycle(3L);
		for (int i = 1; i <= 5; i++) {
			st.pushProperties("r-" + i, props("a|x", "v" + i), 3L);
			st.pushStats("r-" + i, stats("a|s", i), 3L);
			T.check(st.queuedEntries() < 4, "queue bounded after object " + i
					+ ": " + st.queuedEntries());
		}
		T.eq(4, s.batches.size(), "two in-walk flushes, stats and "
				+ "properties each");
		T.check(lines.isEmpty(), "no line per flush: " + lines);
		st.endPushCycle();
		T.eq(6, s.batches.size(), "the rest at the end");
		T.eq(5, s.batchedProps().size(), "every resource's properties");
		T.eq(5, s.batchedStats().size(), "every resource's stats");
		T.eq(1, lines.size(), "one summary for the cycle: " + lines);
		T.check(lines.get(0).contains("5 resource(s) with stats and 5 with "
				+ "properties") && lines.get(0).contains("(3 flushes)"),
				lines.get(0));
		T.check(ComplianceStitcher.FLUSH_ENTRIES == 500
				&& ComplianceStitcher.FLUSH_BYTES == 16L * 1024 * 1024,
				"production thresholds");
	}

	/** Review W3: the byte estimate also triggers a flush. */
	static void byteThresholdFlush() {
		FakeSuiteApi s = new FakeSuiteApi();
		ComplianceStitcher st = logging(s, new ArrayList<String>());
		st.setFlushThresholds(Integer.MAX_VALUE, 2000);
		st.beginPushCycle(3L);
		StringBuilder big = new StringBuilder();
		for (int i = 0; i < 2100; i++) big.append('x');
		st.pushProperties("r-1", props("a|Description", big.toString()), 3L);
		T.eq(1, s.batches.size(), "sent once over the byte estimate");
		T.eq(0, st.queuedEntries(), "queue empty");
		st.endPushCycle();
	}

	/**
	 * Review W2: with Stop Collecting requested, a threshold flush sends
	 * nothing and the abandoned cycle drops the queue with one WARN.
	 */
	static void stopSkipsFlushAndDropsQueue() {
		FakeSuiteApi s = new FakeSuiteApi();
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.setFlushThresholds(2, Long.MAX_VALUE);
		boolean[] stop = {false};
		st.setStopRequested(() -> stop[0]);
		st.beginPushCycle(4L);
		st.pushStats("r-1", stats("a|s", 1), 4L);
		st.pushStats("r-2", stats("a|s", 1), 4L);
		T.eq(1, s.batches.size(), "in-walk flush before the stop");
		stop[0] = true;
		st.pushStats("r-3", stats("a|s", 1), 4L);
		st.pushStats("r-4", stats("a|s", 1), 4L);
		T.eq(1, s.batches.size(), "no flush after the stop");
		st.abandonPushCycle("cycle stopped (test)");
		T.eq(1, s.batches.size(), "the queue is dropped, not sent");
		T.eq(0, st.queuedEntries(), "queue cleared");
		String w = Build96StitcherTest.line(lines, "were not sent");
		T.check(w != null && w.startsWith("WARN ") && w.contains("2 queued "
				+ "resource entr(ies)"), "one WARN: " + lines);
		T.check(Build96StitcherTest.line(lines, "Suite API push: 2 resource")
				!= null, "the summary of what was sent: " + lines);
		// A push after the abandon goes out at once (cycle closed).
		stop[0] = false;
		st.pushStats("r-5", stats("a|s", 1), 4L);
		T.eq(2, s.batches.size(), "cycle closed by the abandon");
	}

	/** Review W2: a stop between the stats and properties calls. */
	static void stopBetweenHalves() {
		FakeSuiteApi s = new FakeSuiteApi();
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		boolean[] stop = {false};
		st.setStopRequested(() -> stop[0]);
		s.beforeBatch = () -> stop[0] = true;
		st.beginPushCycle(4L);
		st.pushStats("r-1", stats("a|s", 1), 4L);
		st.pushProperties("r-1", props("a|x", "1"), 4L);
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.eq(1, s.batches.size(), "stats sent, properties not");
		T.check(s.batches.get(0).isStats(), "the stats call");
		T.eq(1, o.skipped, "properties counted not delivered");
		T.check(lines.get(0).contains("Stop Collecting was requested"),
				lines.get(0));
	}

	/**
	 * Codex P2 on PR #70: a half is split into slices of at most 100
	 * resources and the byte cap, each one framework request; the byte
	 * estimate is an upper bound of the framework's JSON.
	 */
	static void slicesAreOneRequestEach() {
		Map<String, Map<String, String>> half = new LinkedHashMap<>();
		for (int i = 0; i < 250; i++) half.put("r-" + i, props("a|x", "v"));
		List<Map<String, Map<String, String>>> sl = ComplianceStitcher.slices(
				half, ComplianceStitcher.SLICE_RESOURCES,
				ComplianceStitcher.SLICE_BYTES);
		T.eq(3, sl.size(), "250 small resources: 100, 100, 50");
		T.eq(100, sl.get(0).size(), "first slice at the resource cap");
		T.eq(50, sl.get(2).size(), "last slice");
		StringBuilder big = new StringBuilder();
		for (int i = 0; i < 250_000; i++) big.append('x');
		Map<String, Map<String, String>> heavy = new LinkedHashMap<>();
		for (int i = 0; i < 5; i++) {
			heavy.put("r-" + i, props("a|Description", big.toString()));
		}
		sl = ComplianceStitcher.slices(heavy, 100,
				ComplianceStitcher.SLICE_BYTES);
		T.eq(3, sl.size(), "5 x 250 KB: two per slice under 600 KB");
		for (Map<String, Map<String, String>> m : sl) {
			long bytes = 0;
			for (Map.Entry<String, Map<String, String>> e : m.entrySet()) {
				bytes += e.getKey().length() + 80;
				for (Map.Entry<String, String> v : e.getValue().entrySet()) {
					bytes += v.getKey().length() + v.getValue().length() + 60;
				}
			}
			T.check(bytes < 1_000_000, "a slice fits one framework request");
		}
		T.eq(16L, ComplianceStitcher.jsonBytes("a\"\u00e9\u20ac\n"),
				"quotes 2, a 1, \\\" 2, e-acute 2, euro 3, newline 6");
		T.check(ComplianceStitcher.SLICE_RESOURCES == 100
				&& ComplianceStitcher.SLICE_BYTES == 600_000L,
				"production slice caps");
	}

	/**
	 * Codex P2 on PR #70: a stop that arrives after the first slice of a
	 * multi-slice flush sends no further request.
	 */
	static void stopAfterFirstSlice() {
		FakeSuiteApi s = new FakeSuiteApi();
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.setSliceCaps(2, Long.MAX_VALUE);
		boolean[] stop = {false};
		st.setStopRequested(() -> stop[0]);
		s.beforeBatch = () -> stop[0] = true;
		st.beginPushCycle(8L);
		for (int i = 1; i <= 5; i++) {
			st.pushStats("r-" + i, stats("a|s", i), 8L);
			st.pushProperties("r-" + i, props("a|x", "v"), 8L);
		}
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.eq(1, s.batches.size(), "only the first slice went out");
		T.check(s.batches.get(0).isStats(), "a stats slice");
		T.eq(2, s.batches.get(0).stats.size(), "two resources in it");
		T.eq(8, o.skipped, "1 stats slice and 5 properties not delivered");
		T.check(lines.get(0).contains("Stop Collecting was requested"),
				lines.get(0));
	}

	/**
	 * Codex P2 on PR #70: the budget runs out during an in-walk flush. The
	 * rest goes back to the queue and the end-of-cycle flush sends it
	 * (stats before properties), so nothing is lost and the rollup lands.
	 */
	static void budgetDefersInWalkSlices() {
		FakeSuiteApi s = new FakeSuiteApi();
		List<String> lines = new ArrayList<>();
		ComplianceStitcher st = logging(s, lines);
		st.setSliceCaps(2, Long.MAX_VALUE);
		st.setFlushThresholds(8, Long.MAX_VALUE);
		String[] over = {null};
		st.setBudgetExhausted(() -> over[0]);
		s.beforeBatch = () -> over[0] = "budget used up";
		st.beginPushCycle(8L);
		for (int i = 1; i <= 4; i++) {
			st.pushStats("r-" + i, stats("a|s", i), 8L);
			st.pushProperties("r-" + i, props("a|x", "v" + i), 8L);
		}
		T.eq(1, s.batches.size(), "the in-walk flush stopped at the budget");
		T.eq(6, st.queuedEntries(), "the rest back in the queue");
		st.pushStats(AdapterHarness.VC_RESOURCE,
				stats(ComplianceRollup.INCOMPLETE_KEY, 1), 8L);
		ComplianceStitcher.BatchOutcome o = st.endPushCycle();
		T.check(o.isClean(), "clean: " + o);
		T.eq(4, s.batchedStats().size() - 1, "every object's stats");
		T.eq(4, s.batchedProps().size(), "every object's properties");
		T.near(1.0, s.stored(AdapterHarness.VC_RESOURCE,
				ComplianceRollup.INCOMPLETE_KEY), "the rollup landed");
		boolean propsSeen = false;
		for (int i = 1; i < s.batches.size(); i++) {
			if (!s.batches.get(i).isStats()) propsSeen = true;
			else T.check(!propsSeen, "stats before properties at the end");
		}
		T.eq(1, lines.size(), "one summary: " + lines);
	}

	/**
	 * The real cycle (AdapterHarness, 3 hosts and 4 VMs): one stats call and
	 * one properties call at one timestamp, carrying every host's and VM's
	 * properties and score, and the vCenter rollup.
	 */
	static void cycleIsOnePushAtOneTimestamp() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02", "host-12", "esx03")) {
			h.vm("vm-1", "app01", "host-10").vm("vm-2", "app02", "host-10")
					.vm("vm-3", "app03", "host-11")
					.vm("vm-4", "app04", "host-12");
			long before = System.currentTimeMillis();
			h.cycle();
			T.eq(2, h.suite.batches.size(), "one stats and one properties "
					+ "call per cycle");
			T.check(h.suite.batches.get(0).isStats(), "stats first");
			long ts = h.suite.batches.get(0).ts;
			T.eq(ts, h.suite.batches.get(1).ts, "one timestamp");
			T.check(ts >= before && ts <= System.currentTimeMillis(),
					"stamped with the cycle start");
			Map<String, Map<String, String>> bp = h.suite.batchedProps();
			Map<String, Map<String, Double>> bs = h.suite.batchedStats();
			Set<String> want = new LinkedHashSet<>();
			for (String m : h.hosts.keySet()) want.add("r-" + m);
			for (String m : h.vms.keySet()) want.add("r-" + m);
			for (String rid : want) {
				Map<String, String> p = bp.get(rid);
				T.check(p != null && p.containsKey(K + "profile_name"),
						rid + " profile_name");
				Map<String, Double> st = bs.get(rid);
				T.check(st != null && st.containsKey(K + "score"),
						rid + " score");
			}
			T.check(bs.get(AdapterHarness.VC_RESOURCE).containsKey(
					ComplianceRollup.INCOMPLETE_KEY), "the vCenter rollup");
			Set<String> extra = new LinkedHashSet<>(bp.keySet());
			extra.addAll(bs.keySet());
			extra.removeAll(want);
			extra.remove(AdapterHarness.VC_RESOURCE);
			T.check(extra.isEmpty(), "no unknown resource: " + extra);
			T.check(h.logged("Pushed 1") || h.logged("rollup stat(s) to "
					+ "vCenter"), "rollup line after the send (N2)");
		}
	}

	private static ComplianceStitcher swapLoggingStitcher(AdapterHarness h,
			List<String> lines) throws Exception {
		ComplianceStitcher st = logging(h.suite, lines);
		Field f = ComplianceAdapter.class.getDeclaredField("configured");
		f.setAccessible(true);
		f.set(h.adapter, new Configured<SuiteApiStitcher,
				ComplianceStitcher>(h.holder.account, h.client,
				new BenchmarkLoader(), null, st, false));
		return st;
	}

	/** A non-clean batch never fails the cycle; the next cycle pushes again. */
	static void cycleSurvivesNotCleanBatch() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			List<String> lines = Collections.synchronizedList(
					new ArrayList<String>());
			swapLoggingStitcher(h, lines);
			h.suite.batchAnswer = new ComplianceStitcher.BatchOutcome(0, 0,
					1, 0, 2, 0, true);
			h.cycle();   // must not throw
			T.check(h.logged("ComplianceAdapter collection complete"),
					"the cycle completed");
			T.check(h.logged("Rollup push of"), "the rollup line says it "
					+ "may not have landed (N2)");
			int warns = 0;
			for (String l : lines) {
				if (l.contains("Suite API push")) warns++;
			}
			T.eq(1, warns, "one summary line per cycle: " + lines);
			h.suite.batchAnswer = null;
			int n = h.suite.batches.size();
			h.cycle();
			T.eq(n + 2, h.suite.batches.size(), "the next cycle pushes");
			String info = Build96StitcherTest.line(lines, "Suite API push: ");
			T.check(info != null && !info.contains("replaced"),
					"clean, no key pushed twice: " + lines);
		}
	}

	/**
	 * Review W4: a cycle that cannot reach vCenter delivers
	 * Rollup|incomplete = 1 to the vCenter object (sent at once by the
	 * marker; the finally's flush has nothing left) and still throws.
	 */
	static void notReachedMarkerDelivered() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			h.cycle();
			int n = h.suite.batches.size();
			h.vc.loginFails = true;
			h.client.disconnect();
			boolean threw = false;
			try {
				h.cycle();
			} catch (Exception e) {
				threw = true;
			}
			T.check(threw, "the cycle still fails");
			T.eq(n + 1, h.suite.batches.size(), "one stats call");
			FakeSuiteApi.Batch b = h.suite.batches.get(n);
			T.eq(Collections.singletonMap(AdapterHarness.VC_RESOURCE,
					Collections.singletonMap(ComplianceRollup.INCOMPLETE_KEY,
							1.0)), b.stats, "only Rollup|incomplete = 1");
			T.check(h.logged("= 1 pushed to resource "
					+ AdapterHarness.VC_RESOURCE), "logged after the send");
		}
	}

	/**
	 * Review N3: the cached vCenter object id is no longer listed in VCF
	 * Ops (replaced): the marker resolves the entered host instead of
	 * pushing to an id the batch would drop silently.
	 */
	static void staleCachedVcIdNotUsed() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01")) {
			h.cycle();
			h.suite.bodies.put("resourceKind=VMwareAdapter+Instance&",
					"{\"pageInfo\":{\"totalCount\":1},\"resourceList\":[{"
					+ "\"identifier\":\"r-vc-new\",\"resourceKey\":{"
					+ "\"name\":\"vc\",\"resourceIdentifiers\":["
					+ "{\"identifierType\":{\"name\":\"VCURL\"},\"value\":"
					+ "\"vc.lab.example\"}]}}]}");
			int n = h.suite.batches.size();
			h.vc.loginFails = true;
			h.client.disconnect();
			try {
				h.cycle();
			} catch (Exception expected) {
				// the cycle fails; the marker is what is checked
			}
			T.eq(n + 1, h.suite.batches.size(), "one stats call");
			T.check(h.suite.batches.get(n).stats.containsKey("r-vc-new"),
					"pushed to the listed object: "
							+ h.suite.batches.get(n).stats.keySet());
			T.check(!h.suite.batches.get(n).stats.containsKey(
					AdapterHarness.VC_RESOURCE), "not to the stale id");
			T.check(h.logged("is no longer listed in VCF Ops"), "said so");
		}
	}

	/**
	 * Review W2/W4: Stop Collecting mid-walk. Matching build 103, nothing
	 * goes to the Suite API after the stop (no rollup, no queued objects);
	 * what the in-walk flushes sent before it stays sent.
	 */
	static void stopMidWalkSendsNothingMore() throws Exception {
		try (AdapterHarness h = new AdapterHarness("host-10", "esx01",
				"host-11", "esx02")) {
			for (int i = 1; i <= 6; i++) {
				h.vm("vm-" + i, "app0" + i, "host-10");
			}
			List<String> lines = Collections.synchronizedList(
					new ArrayList<String>());
			ComplianceStitcher st = swapLoggingStitcher(h, lines);
			st.setFlushThresholds(3, Long.MAX_VALUE);
			// The first in-walk flush asks to stop: its properties half and
			// everything after is not sent.
			h.suite.beforeBatch = () -> h.adapter.testAbort = true;
			boolean stopped = false;
			try {
				h.cycle();
			} catch (InterruptedException e) {
				stopped = true;
			}
			T.check(stopped, "the cycle was abandoned");
			T.eq(1, h.suite.batches.size(), "only the call in flight when "
					+ "the stop came");
			T.check(!h.suite.batchedStats().containsKey(
					AdapterHarness.VC_RESOURCE)
					|| !h.suite.batchedStats().get(AdapterHarness.VC_RESOURCE)
							.containsKey(ComplianceRollup.INCOMPLETE_KEY),
					"no rollup after a stop, as in build 103");
			T.check(Build96StitcherTest.line(lines, "were not sent") != null,
					"the dropped queue is named: " + lines);
			T.eq(0, st.queuedEntries(), "queue cleared");
			h.adapter.testAbort = false;
			h.suite.beforeBatch = null;
		}
	}

	/**
	 * Review N4: the adapter's framework wrapper (suiteApi) and its
	 * field-for-field mapping run, through the stub's default batch.
	 */
	static void adapterMappingAndStubDefault() throws Exception {
		Constructor<SuiteApiBatchResult> c = SuiteApiBatchResult.class
				.getDeclaredConstructor(int.class, int.class, int.class,
						int.class, int.class, int.class, boolean.class);
		c.setAccessible(true);
		SuiteApiBatchResult r = c.newInstance(1, 2, 3, 4, 5, 6, true);
		Method m = ComplianceAdapter.class.getDeclaredMethod("outcome",
				SuiteApiBatchResult.class);
		m.setAccessible(true);
		ComplianceStitcher.BatchOutcome o =
				(ComplianceStitcher.BatchOutcome) m.invoke(null, r);
		T.eq("sent=1 batchesOk=2 batchesFailed=3 fellBack=4 skipped=5 "
				+ "dropped=6 stopped=true", o.toString(), "field for field");

		List<String> perId = new ArrayList<>();
		SuiteApiStitcher.testFactory = new SuiteApiStitcher.Backend() {
			@Override public String get(String path) { return "{}"; }
			@Override public void pushStats(String id,
					Map<String, Double> s, long ts) {
				perId.add("stats " + id + " " + s + " " + ts);
			}
			@Override public void pushProperties(String id,
					Map<String, String> p, long ts) {
				perId.add("props " + id + " " + p + " " + ts);
			}
		};
		try {
			SuiteApiStitcher sas = SuiteApiStitcher.create(null, null);
			Method w = ComplianceAdapter.class.getDeclaredMethod("suiteApi",
					SuiteApiStitcher.class);
			w.setAccessible(true);
			ComplianceStitcher.SuiteApi api =
					(ComplianceStitcher.SuiteApi) w.invoke(null, sas);
			ComplianceStitcher st = new ComplianceStitcher(api, null);
			st.beginPushCycle(42L);
			st.pushProperties("r-1", props("a|x", "1"), 42L);
			st.pushStats("r-1", stats("a|s", 1), 42L);
			ComplianceStitcher.BatchOutcome out = st.endPushCycle();
			T.eq(java.util.Arrays.asList("stats r-1 {a|s=1.0} 42",
					"props r-1 {a|x=1} 42"), perId, "stats first, through "
							+ "the wrapper and the stub default");
			T.eq("sent=2 batchesOk=2 batchesFailed=0 fellBack=0 skipped=0 "
					+ "dropped=0 stopped=false", out.toString(), "mapped");
		} finally {
			SuiteApiStitcher.testFactory = null;
		}
	}
}
