package com.vcfcf.adapters.compliance;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * v3 (build 57): per-vCenter compliance rollup, pushed as metrics onto that
 * vCenter's VMWARE {@code VMwareAdapter Instance} object.
 *
 * <p>Why the vCenter object and not ComplianceWorld: every adapter instance
 * registers the SAME ComplianceWorld resource (identifier
 * {@code world_id=compliance_world}), so with three vCenters its Summary
 * values were whichever instance wrote last. Each instance owns exactly one
 * vCenter object, so a rollup there is unambiguous.
 *
 * <p>Keys ({@code <K>} in All, Host, VM, vCenter, Cluster, vDS, Portgroup):
 * <pre>
 * VCF-CF Compliance|Rollup|&lt;K&gt;|scored          objects with a score this cycle
 *                                                (at least one control attempted)
 * VCF-CF Compliance|Rollup|&lt;K&gt;|non_compliant   objects with fail_count &gt; 0 (build 95: what was read)
 * VCF-CF Compliance|Rollup|&lt;K&gt;|no_benchmark    objects whose version has no SCG
 * VCF-CF Compliance|Rollup|&lt;K&gt;|score_sum       sum of those scores
 * VCF-CF Compliance|Rollup|&lt;K&gt;|avg_score       score_sum / scored (omitted when scored == 0)
 * VCF-CF Compliance|Rollup|&lt;K&gt;|unmatched       per kind, not All (build 88): objects with
 *                                                no matching VCF Ops resource, not counted
 *                                                anywhere else
 * VCF-CF Compliance|Rollup|&lt;K&gt;|controls_evaluated   build 95: controls passed plus failed,
 *                                                summed over the kind's scored objects
 * VCF-CF Compliance|Rollup|&lt;K&gt;|controls_passed      build 95: controls passed
 * VCF-CF Compliance|Rollup|&lt;K&gt;|pass_rate            build 95: controls_passed /
 *                                                controls_evaluated * 100, omitted when
 *                                                controls_evaluated == 0
 * VCF-CF Compliance|Rollup|VM|skipped_pods        vSphere Pod VMs (guest id crx*), out of scope
 * VCF-CF Compliance|Rollup|Benchmark|&lt;B&gt;|objects  objects the benchmark B was applied to
 * </pre>
 * {@code <B>} is SCG_6.7, SCG_7.0, SCG_8.0, SCG_9.0, SCG_9.1, none and
 * unknown (always pushed, 0 when unused). {@code unknown} counts objects whose governing version could
 * not be read and that had no previous benchmark to fall back on (build 58);
 * since build 95 that bucket is all they are counted in (nothing was read),
 * never no_benchmark.
 *
 * <p>Score rule: an object is scored when at least one control was read
 * (build 95); an object with nothing read (every attempted control
 * unreadable, e.g. a host vCenter reports not responding, or nothing
 * evaluable, e.g. a non-vSAN cluster) contributes no score. The build-49
 * last-known-score carry-forward and the {@code Rollup|Host|scored_stale}
 * key stay retired. No-benchmark objects are counted, never scored.
 *
 * <p>Scope rule (build 88, Scott 2026-10-12 "Option 1."): the rollup
 * counts only objects the adapter can push to, i.e. objects with a
 * matching VCF Ops resource. An object with no match is recorded with
 * {@link #recordUnmatched} and nowhere else: not in scored, non_compliant,
 * no_benchmark, score_sum, All or a Benchmark bucket. The gap stays
 * visible as {@code Rollup|<K>|unmatched} (0 when none) and in
 * {@link #unmatchedLogLine}. vSphere Pod VMs are out of scope and are
 * recorded with {@link #recordSkippedPod} only ({@code Rollup|VM|skipped_pods}).
 *
 * <p>Pass rate rule (build 95, Scott 2026-10-14 "compliance percentage is
 * basically: Total passing controls/total controls evaluated"): the
 * percentage shown for a kind, a vCenter and the environment is controls
 * passed over controls evaluated, so a port group no longer weighs as much
 * as a vCenter. Evaluated is passed plus failed; unreadable controls are in
 * neither count (never a pass, never in the denominator). Manual review
 * and override-skipped controls never reach the counts. With nothing
 * evaluated, pass_rate is omitted, never 100. The object-mean keys
 * (score_sum, avg_score) are unchanged.
 *
 * <p>Unreadable rule (build 95, Scott 2026-10-14, "if we have missing data
 * we just don't log it - but flag the stale metric"): the rollup counts
 * only what was read this cycle. There is no unreadable rollup key (the
 * {@code controls_unreadable} key of the first build 95 draft is gone);
 * each object carries {@code has_unreadable} and its reason instead, listed
 * on the dashboards. An object with nothing readable (every attempted
 * control unreadable, or its version unreadable with no benchmark to fall
 * back on) is counted only in its Benchmark bucket: not scored, not
 * non-compliant, no controls, no score in score_sum.
 *
 * <p>No SDK dependencies: unit-testable with a plain JDK.
 */
public final class ComplianceRollup {

	public static final String PREFIX = "VCF-CF Compliance|Rollup|";

	/** 0/1: some rollup keys were held back this cycle (build 79). */
	public static final String INCOMPLETE_KEY = PREFIX + "incomplete";

	/** Build 88: unmatched objects named per kind in the INFO line, at most. */
	public static final int UNMATCHED_LOG_CAP = 20;

	/** Benchmark buckets always pushed (0 when unused), in key order. */
	public static final String[] FIXED_BUCKETS = {
			"SCG_6.7", "SCG_7.0", "SCG_8.0", "SCG_9.0", "SCG_9.1",
			BenchmarkSelector.BUCKET_NONE, BenchmarkSelector.BUCKET_UNKNOWN
	};

	/**
	 * Build 92 (review N2): the bucket the removed Custom profile used. It
	 * was pushed only while in use, so an account that was Custom would
	 * keep its last count on the vCenter forever.
	 */
	public static final String RETIRED_CUSTOM_KEY =
			PREFIX + "Benchmark|Custom|objects";

	/**
	 * Build 92 (review N2): add {@link #RETIRED_CUSTOM_KEY} = 0 to a rollup
	 * push, only when the push carries the Benchmark counts (a complete
	 * cycle; an incomplete one holds them back and must not zero one
	 * either). Returns true when added, so the caller does it once.
	 */
	public static boolean zeroRetiredCustom(Map<String, Double> stats) {
		if (!stats.containsKey(PREFIX + "Benchmark|"
				+ BenchmarkSelector.BUCKET_UNKNOWN + "|objects")) {
			return false;
		}
		stats.put(RETIRED_CUSTOM_KEY, 0.0);
		return true;
	}

	private static final class Tally {
		int scored;
		int nonCompliant;
		int noBenchmark;
		double scoreSum;
		int unmatched;   // build 88: per kind only, never summed into All
		long controlsEvaluated;   // build 95: passed + failed
		long controlsPassed;      // build 95
	}

	private final Map<BenchmarkSelector.Kind, Tally> byKind =
			new EnumMap<>(BenchmarkSelector.Kind.class);
	private final Map<String, Integer> byBucket = new LinkedHashMap<>();
	// Build 88: the first UNMATCHED_LOG_CAP unmatched objects per kind.
	private final Map<BenchmarkSelector.Kind, java.util.List<String>>
			unmatchedNames = new EnumMap<>(BenchmarkSelector.Kind.class);
	private int skippedPods;

	// Build 78: kinds whose inventory listing failed this cycle.
	private final java.util.Set<BenchmarkSelector.Kind> incomplete =
			java.util.EnumSet.noneOf(BenchmarkSelector.Kind.class);

	/**
	 * Build 78 (review of build 77, NIT): the inventory listing for
	 * {@code kind} failed this cycle, so its objects were not evaluated.
	 * {@link #toStats} then OMITS that kind's keys, and the cross-kind
	 * {@code All} and {@code Benchmark|<B>|objects} keys, instead of pushing
	 * counts that silently leave those objects out. Omitted keys keep their
	 * previous values in VCF Ops, so the environment totals (the
	 * ComplianceWorld {@code Rollup|Environment} ComputedMetrics, sums of
	 * each vCenter's {@code Rollup|All|*}) stay close to the truth for the
	 * cycle rather than dropping, e.g., every VM of one vCenter. The next
	 * complete cycle pushes everything again.
	 */
	public void markIncomplete(BenchmarkSelector.Kind kind) {
		incomplete.add(kind);
	}

	public java.util.Set<BenchmarkSelector.Kind> incompleteKinds() {
		return java.util.Collections.unmodifiableSet(incomplete);
	}

	public ComplianceRollup() {
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			byKind.put(k, new Tally());
		}
		for (String b : FIXED_BUCKETS) {
			byBucket.put(b, 0);
		}
	}

	/**
	 * Build 88: an object vCenter listed but with no matching VCF Ops
	 * resource this cycle. Counted only in {@code Rollup|<K>|unmatched}:
	 * nothing can be pushed to it, so it is in no other key. Not scored by
	 * the adapter either (the caller skips its reads).
	 */
	public void recordUnmatched(BenchmarkSelector.Kind kind, String name,
			String moid) {
		byKind.get(kind).unmatched++;
		java.util.List<String> names = unmatchedNames.computeIfAbsent(kind,
				k -> new java.util.ArrayList<>());
		if (names.size() < UNMATCHED_LOG_CAP) {
			names.add((name == null ? "(no name)" : name) + " ("
					+ (moid == null ? "no MOID" : moid) + ")");
		}
	}

	/**
	 * Build 88: a vSphere Pod VM (guest id {@code crx*}, see
	 * {@link ComplianceDecisions#isPodGuestId}). Out of scope: counted in
	 * {@code Rollup|VM|skipped_pods} only, never scored, never unmatched.
	 */
	public void recordSkippedPod() {
		skippedPods++;
	}

	public int unmatched(BenchmarkSelector.Kind kind) {
		return byKind.get(kind).unmatched;
	}

	public int skippedPods() {
		return skippedPods;
	}

	/**
	 * Build 88: the one INFO line per cycle for {@code kind}'s unmatched
	 * objects, naming the first {@link #UNMATCHED_LOG_CAP} by name and
	 * MOID; null when there are none.
	 */
	public String unmatchedLogLine(BenchmarkSelector.Kind kind) {
		int n = byKind.get(kind).unmatched;
		if (n == 0) return null;
		java.util.List<String> names = unmatchedNames.get(kind);
		StringBuilder b = new StringBuilder();
		b.append(kind.rollupName).append(": ").append(n)
				.append(" object(s) with no matching VCF Ops resource, not "
						+ "scored and not counted in the rollup this cycle "
						+ "(Rollup|").append(kind.rollupName)
				.append("|unmatched): ");
		b.append(String.join(", ", names));
		if (n > names.size()) {
			b.append(" (+").append(n - names.size()).append(" more)");
		}
		return b.toString();
	}

	/**
	 * Non-compliant rule shared with the per-object push. Build 95
	 * (decision point 7): a failing control that was read. An unreadable
	 * control no longer makes an object non-compliant (builds 63 to 94
	 * did); the object's has_unreadable flag carries it.
	 */
	public static boolean isNonCompliant(int failCount) {
		return failCount > 0;
	}

	/** An object whose version has no SCG (Auto mode only). */
	public void recordNoBenchmark(BenchmarkSelector.Kind kind) {
		byKind.get(kind).noBenchmark++;
		bump(BenchmarkSelector.BUCKET_NONE);
	}

	/**
	 * An object whose governing version could not be read and that had no
	 * benchmark to fall back on (build 58 B2, build 65 W1). Build 95:
	 * nothing was read, so it is counted in the {@code unknown} bucket only:
	 * not scored, not non-compliant, never no_benchmark. Its
	 * has_unreadable flag carries it.
	 */
	public void recordVersionUnreadable(BenchmarkSelector.Kind kind) {
		bump(BenchmarkSelector.BUCKET_UNKNOWN);
	}

	/**
	 * An object evaluated against benchmark {@code bucket}. Build 95: the
	 * counts come from what was read, so the object is scored, and can be
	 * non-compliant, only when at least one control was read
	 * ({@code totalCount > 0}). Nothing read (nothing attempted, or every
	 * attempted control unreadable) adds to the benchmark bucket only.
	 */
	public void recordEvaluated(BenchmarkSelector.Kind kind, String bucket,
			int totalCount, int failCount, int unreadableCount, double score) {
		Tally t = byKind.get(kind);
		bump(bucket);
		if (totalCount <= 0) {
			return;   // nothing read: no score, no counts (build 95)
		}
		if (isNonCompliant(failCount)) {
			t.nonCompliant++;
		}
		t.scored++;
		t.scoreSum += score;
		// Build 95: control counts. totalCount is passed + failed
		// (ComplianceResult), unreadable is in neither.
		int evaluated = Math.max(0, totalCount);
		int failed = Math.min(Math.max(0, failCount), evaluated);
		t.controlsEvaluated += evaluated;
		t.controlsPassed += evaluated - failed;
	}

	private void bump(String bucket) {
		String b = bucket == null ? BenchmarkSelector.BUCKET_NONE : bucket;
		byBucket.merge(b, 1, Integer::sum);
	}

	/** Every rollup stat, keyed by full metric key, in a stable order. */
	public Map<String, Double> toStats() {
		Map<String, Double> out = new LinkedHashMap<>();
		Tally all = new Tally();
		for (Tally t : byKind.values()) {
			all.scored += t.scored;
			all.nonCompliant += t.nonCompliant;
			all.noBenchmark += t.noBenchmark;
			all.scoreSum += t.scoreSum;
			all.controlsEvaluated += t.controlsEvaluated;
			all.controlsPassed += t.controlsPassed;
		}
		boolean complete = incomplete.isEmpty();
		// Build 79 (review of build 78, WARNING): pushed EVERY cycle, never
		// omitted, so it cannot go stale: 1 while any listing failed and
		// keys were held back (the vCenter collection alert fires on it),
		// 0 once a complete cycle pushes everything again.
		out.put(INCOMPLETE_KEY, complete ? 0.0 : 1.0);
		if (complete) {
			put(out, "All", all, false);
		}
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			if (!incomplete.contains(k)) {
				// Build 88: unmatched (and skipped_pods for VM) travel with
				// the kind's other keys: every complete cycle, 0 when none,
				// held back with them when the kind is incomplete (a count
				// the adapter could not take is not a 0).
				put(out, k.rollupName, byKind.get(k), true);
				if (k == BenchmarkSelector.Kind.VM) {
					out.put(PREFIX + "VM|skipped_pods", (double) skippedPods);
				}
			}
		}
		if (!complete) {
			return out;   // All and Benchmark counts would under-count
		}
		for (Map.Entry<String, Integer> e : byBucket.entrySet()) {
			out.put(PREFIX + "Benchmark|" + e.getKey() + "|objects",
					(double) e.getValue());
		}
		return out;
	}

	private static void put(Map<String, Double> out, String name, Tally t,
			boolean perKind) {
		String p = PREFIX + name + "|";
		out.put(p + "scored", (double) t.scored);
		out.put(p + "non_compliant", (double) t.nonCompliant);
		out.put(p + "no_benchmark", (double) t.noBenchmark);
		out.put(p + "score_sum", t.scoreSum);
		if (perKind) {
			out.put(p + "unmatched", (double) t.unmatched);
		}
		// No-sentinel contract: no average without at least one real score.
		if (t.scored > 0) {
			out.put(p + "avg_score", t.scoreSum / t.scored);
		}
		// Build 95: control counts and the pass rate. Same no-sentinel
		// contract: no pass_rate without at least one evaluated control.
		out.put(p + "controls_evaluated", (double) t.controlsEvaluated);
		out.put(p + "controls_passed", (double) t.controlsPassed);
		Double rate = passRate(t.controlsPassed, t.controlsEvaluated);
		if (rate != null) {
			out.put(p + "pass_rate", rate);
		}
	}

	/**
	 * Build 95: passed / evaluated * 100, or null when nothing was
	 * evaluated (no data, never a substituted 100).
	 */
	public static Double passRate(long passed, long evaluated) {
		if (evaluated <= 0) return null;
		return (double) passed / evaluated * 100.0;
	}
}
