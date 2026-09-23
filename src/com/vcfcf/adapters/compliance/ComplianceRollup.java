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
 * VCF-CF Compliance|Rollup|&lt;K&gt;|non_compliant   objects with fail_count &gt; 0 or unreadable_count &gt; 0
 * VCF-CF Compliance|Rollup|&lt;K&gt;|no_benchmark    objects whose version has no SCG
 * VCF-CF Compliance|Rollup|&lt;K&gt;|score_sum       sum of those scores
 * VCF-CF Compliance|Rollup|&lt;K&gt;|avg_score       score_sum / scored (omitted when scored == 0)
 * VCF-CF Compliance|Rollup|Benchmark|&lt;B&gt;|objects  objects the benchmark B was applied to
 * </pre>
 * {@code <B>} is SCG_6.7, SCG_7.0, SCG_8.0, SCG_9.0, SCG_9.1, none and
 * unknown (always pushed, 0 when unused) plus Custom when a custom profile
 * is in use. {@code unknown} counts objects whose governing version could
 * not be read and that had no previous benchmark to fall back on (build 58);
 * they are non-compliant (unreadable), never no_benchmark.
 *
 * <p>Score rule (build 63, owner decision): an object's score counts
 * unreadable controls as failing ({@link ControlEvaluator#score}), so an
 * object with every attempted control unreadable scores 0 and IS counted
 * in scored / score_sum. Only an object with nothing attempted (nothing
 * evaluable, e.g. a non-vSAN cluster) contributes no score. The build-49
 * last-known-score carry-forward for unreadable hosts and the
 * {@code Rollup|Host|scored_stale} key are retired: an unreadable host now
 * contributes its real score, 0. A version-unreadable object with no
 * previous benchmark also scores 0 (build 65). No-benchmark objects are
 * counted, never scored.
 *
 * <p>No SDK dependencies: unit-testable with a plain JDK.
 */
public final class ComplianceRollup {

	public static final String PREFIX = "VCF-CF Compliance|Rollup|";

	/** 0/1: some rollup keys were held back this cycle (build 79). */
	public static final String INCOMPLETE_KEY = PREFIX + "incomplete";

	/** Benchmark buckets always pushed (0 when unused), in key order. */
	public static final String[] FIXED_BUCKETS = {
			"SCG_6.7", "SCG_7.0", "SCG_8.0", "SCG_9.0", "SCG_9.1",
			BenchmarkSelector.BUCKET_NONE, BenchmarkSelector.BUCKET_UNKNOWN
	};

	private static final class Tally {
		int scored;
		int nonCompliant;
		int noBenchmark;
		double scoreSum;
	}

	private final Map<BenchmarkSelector.Kind, Tally> byKind =
			new EnumMap<>(BenchmarkSelector.Kind.class);
	private final Map<String, Integer> byBucket = new LinkedHashMap<>();

	// Build 78: kinds whose inventory listing failed this cycle.
	private final java.util.Set<BenchmarkSelector.Kind> incomplete =
			java.util.EnumSet.noneOf(BenchmarkSelector.Kind.class);

	/**
	 * Build 78 (review of build 77, NIT): the inventory listing for
	 * {@code kind} failed this cycle, so its objects were not evaluated.
	 * {@link #toStats} then OMITS that kind's keys, and the cross-kind
	 * {@code All} and {@code Benchmark|<B>|objects} keys, instead of pushing
	 * counts that silently leave those objects out. Omitted keys keep their
	 * previous values in VCF Ops, so the environment super metrics (sums of
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
	 * An object whose governing version could not be read and that had no
	 * benchmark to fall back on (build 58 B2, build 65 W1). Nothing was
	 * collected, so by the build 63 rule it scores 0: counted as scored
	 * with 0, non-compliant, in the {@code unknown} bucket, never as
	 * no_benchmark.
	 */
	public void recordVersionUnreadable(BenchmarkSelector.Kind kind) {
		Tally t = byKind.get(kind);
		t.nonCompliant++;
		t.scored++;
		t.scoreSum += 0.0;
		bump(BenchmarkSelector.BUCKET_UNKNOWN);
	}

	/**
	 * An object evaluated against benchmark {@code bucket}. Scored (build
	 * 63) when at least one control was attempted
	 * ({@code totalCount + unreadableCount > 0}); {@code score} is then the
	 * unreadable-counts-as-failing score. Nothing attempted adds to the
	 * benchmark bucket only.
	 */
	public void recordEvaluated(BenchmarkSelector.Kind kind, String bucket,
			int totalCount, int failCount, int unreadableCount, double score) {
		Tally t = byKind.get(kind);
		bump(bucket);
		if (isNonCompliant(failCount, unreadableCount)) {
			t.nonCompliant++;
		}
		if (totalCount + unreadableCount > 0) {
			t.scored++;
			t.scoreSum += score;
		}
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
		}
		boolean complete = incomplete.isEmpty();
		// Build 79 (review of build 78, WARNING): pushed EVERY cycle, never
		// omitted, so it cannot go stale: 1 while any listing failed and
		// keys were held back (the vCenter collection alert fires on it),
		// 0 once a complete cycle pushes everything again.
		out.put(INCOMPLETE_KEY, complete ? 0.0 : 1.0);
		if (complete) {
			put(out, "All", all);
		}
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			if (!incomplete.contains(k)) {
				put(out, k.rollupName, byKind.get(k));
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
