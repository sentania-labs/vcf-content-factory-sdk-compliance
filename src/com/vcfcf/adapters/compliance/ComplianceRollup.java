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
 * VCF-CF Compliance|Rollup|&lt;K&gt;|non_compliant   objects with fail_count &gt; 0 or unreadable_count &gt; 0
 * VCF-CF Compliance|Rollup|&lt;K&gt;|no_benchmark    objects whose version has no SCG
 * VCF-CF Compliance|Rollup|&lt;K&gt;|score_sum       sum of those scores
 * VCF-CF Compliance|Rollup|&lt;K&gt;|avg_score       score_sum / scored (omitted when scored == 0)
 * VCF-CF Compliance|Rollup|Host|scored_stale     hosts scored from their last-known score
 * VCF-CF Compliance|Rollup|Benchmark|&lt;B&gt;|objects  objects the benchmark B was applied to
 * </pre>
 * {@code <B>} is SCG_6.7, SCG_7.0, SCG_8.0, SCG_9.0, SCG_9.1 and none
 * (always pushed, 0 when unused) plus Custom when a custom profile is in
 * use.
 *
 * <p>Cardinal-rule discipline: an object with {@code total_count == 0}
 * (nothing evaluable, or everything unreadable) never contributes a score.
 * The one exception is inherited from build 49 (task #16, owner decision): a
 * host that is channel-unreadable this cycle contributes its LAST-KNOWN
 * score so the host average is not flattered by a shrinking denominator;
 * such hosts are counted in {@code Host|scored_stale}. No-benchmark objects
 * are counted, never scored, and never non-compliant.
 *
 * <p>No SDK dependencies: unit-testable with a plain JDK.
 */
public final class ComplianceRollup {

	public static final String PREFIX = "VCF-CF Compliance|Rollup|";

	/** Benchmark buckets always pushed (0 when unused), in key order. */
	public static final String[] FIXED_BUCKETS = {
			"SCG_6.7", "SCG_7.0", "SCG_8.0", "SCG_9.0", "SCG_9.1",
			BenchmarkSelector.BUCKET_NONE
	};

	private static final class Tally {
		int scored;
		int nonCompliant;
		int noBenchmark;
		int stale;
		double scoreSum;
	}

	private final Map<BenchmarkSelector.Kind, Tally> byKind =
			new EnumMap<>(BenchmarkSelector.Kind.class);
	private final Map<String, Integer> byBucket = new LinkedHashMap<>();

	public ComplianceRollup() {
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			byKind.put(k, new Tally());
		}
		for (String b : FIXED_BUCKETS) {
			byBucket.put(b, 0);
		}
	}

	/** Non-compliant rule shared with the per-object push. */
	public static boolean isNonCompliant(int failCount, int unreadableCount) {
		return failCount > 0 || unreadableCount > 0;
	}

	/** An object whose version has no SCG (Auto mode only). */
	public void recordNoBenchmark(BenchmarkSelector.Kind kind) {
		byKind.get(kind).noBenchmark++;
		bump(BenchmarkSelector.BUCKET_NONE);
	}

	/**
	 * An object evaluated against benchmark {@code bucket}. A
	 * {@code totalCount == 0} result (nothing scored) adds to the benchmark
	 * bucket and, when it carries unreadable controls, to non_compliant,
	 * but never to scored / score_sum.
	 */
	public void recordEvaluated(BenchmarkSelector.Kind kind, String bucket,
			int totalCount, int failCount, int unreadableCount, double score) {
		Tally t = byKind.get(kind);
		bump(bucket);
		if (isNonCompliant(failCount, unreadableCount)) {
			t.nonCompliant++;
		}
		if (totalCount > 0) {
			t.scored++;
			t.scoreSum += score;
		}
	}

	/**
	 * A host that is unreadable this cycle and was recorded with
	 * {@link #recordEvaluated} (totalCount 0) contributes its last-known
	 * score. Call at most once per host, after recordEvaluated.
	 */
	public void recordStaleScore(BenchmarkSelector.Kind kind,
			double lastKnownScore) {
		Tally t = byKind.get(kind);
		t.scored++;
		t.stale++;
		t.scoreSum += lastKnownScore;
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
			all.stale += t.stale;
			all.scoreSum += t.scoreSum;
		}
		put(out, "All", all);
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			put(out, k.rollupName, byKind.get(k));
		}
		out.put(PREFIX + "Host|scored_stale",
				(double) byKind.get(BenchmarkSelector.Kind.HOST).stale);
		for (Map.Entry<String, Integer> e : byBucket.entrySet()) {
			out.put(PREFIX + "Benchmark|" + e.getKey() + "|objects",
					(double) e.getValue());
		}
		return out;
	}

	private static void put(Map<String, Double> out, String name, Tally t) {
		String p = PREFIX + name + "|";
		out.put(p + "scored", (double) t.scored);
		out.put(p + "non_compliant", (double) t.nonCompliant);
		out.put(p + "no_benchmark", (double) t.noBenchmark);
		out.put(p + "score_sum", t.scoreSum);
		// No-sentinel contract: no average without at least one real score.
		if (t.scored > 0) {
			out.put(p + "avg_score", t.scoreSum / t.scored);
		}
	}
}
