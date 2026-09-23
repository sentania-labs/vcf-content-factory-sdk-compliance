package com.vcfcf.adapters.compliance;

import java.util.Map;

/** Rollup arithmetic (build 57), including no_benchmark and unreadable. */
public final class ComplianceRollupTest {

	private static final String P = ComplianceRollup.PREFIX;

	public static void main(String[] args) {
		// Build 63 score rule: unreadable counts as failing.
		T.near(90, ControlEvaluator.score(9, 1, 0), "9/10");
		T.near(80, ControlEvaluator.score(8, 0, 2),
				"partial unreadable lowers the score (8 of 10 attempted)");
		T.near(0, ControlEvaluator.score(0, 0, 40), "all unreadable scores 0");
		T.near(80, ControlEvaluator.score(4, 0, 1), "4 of 5");

		ComplianceRollup r = new ComplianceRollup();
		// Hosts: 90 (fails), 100 (clean), all-unreadable (0), partially
		// unreadable (80), and one no-benchmark (ESXi 10.0).
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_8.0", 10, 1, 0,
				ControlEvaluator.score(9, 1, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 10, 0, 0,
				ControlEvaluator.score(10, 0, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 0, 0, 40,
				ControlEvaluator.score(0, 0, 40));
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_7.0", 8, 0, 2,
				ControlEvaluator.score(8, 0, 2));
		r.recordNoBenchmark(BenchmarkSelector.Kind.HOST);
		// VMs: one clean, one with an unreadable control.
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_8.0", 4, 0, 0,
				ControlEvaluator.score(4, 0, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_8.0", 4, 0, 1,
				ControlEvaluator.score(4, 0, 1));
		// vCenter scored 50; a non-vSAN cluster (nothing attempted).
		r.recordEvaluated(BenchmarkSelector.Kind.VCENTER, "SCG_9.1", 2, 1, 0,
				ControlEvaluator.score(1, 1, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.CLUSTER, "SCG_9.1", 0, 0, 0,
				ControlEvaluator.score(0, 0, 0));
		// Portgroup with no benchmark; vDS nothing at all.
		r.recordNoBenchmark(BenchmarkSelector.Kind.PORTGROUP);

		Map<String, Double> s = r.toStats();

		T.near(4, s.get(P + "Host|scored"),
				"all-unreadable host is scored (0), not skipped");
		T.near(270, s.get(P + "Host|score_sum"), "host sum 90+100+0+80");
		T.near(67.5, s.get(P + "Host|avg_score"), "host avg");
		T.near(3, s.get(P + "Host|non_compliant"),
				"host non-compliant: fail + all-unreadable + partial");
		T.near(1, s.get(P + "Host|no_benchmark"), "host no benchmark");
		T.check(!s.containsKey(P + "Host|scored_stale"),
				"scored_stale retired in build 63");

		T.near(2, s.get(P + "VM|scored"), "vm scored");
		T.near(1, s.get(P + "VM|non_compliant"), "vm unreadable counts");
		T.near(90, s.get(P + "VM|avg_score"), "vm avg (100 + 80) / 2");

		T.near(1, s.get(P + "vCenter|scored"), "vc scored");
		T.near(50, s.get(P + "vCenter|avg_score"), "vc avg");
		T.near(1, s.get(P + "vCenter|non_compliant"), "vc non-compliant");

		T.near(0, s.get(P + "Cluster|scored"), "nothing attempted: not scored");
		T.near(0, s.get(P + "Cluster|non_compliant"), "cluster not non-compl");
		T.check(!s.containsKey(P + "Cluster|avg_score"),
				"no avg without a score (no placeholder)");
		T.check(!s.containsKey(P + "vDS|avg_score"), "vDS no avg");
		T.near(0, s.get(P + "vDS|scored"), "vDS zero");
		T.near(1, s.get(P + "Portgroup|no_benchmark"), "pg no benchmark");

		T.near(7, s.get(P + "All|scored"), "all scored 4+2+1");
		T.near(500, s.get(P + "All|score_sum"), "all sum 270+180+50");
		T.near(500.0 / 7, s.get(P + "All|avg_score"), "all weighted avg");
		T.near(5, s.get(P + "All|non_compliant"), "all non-compliant 3+1+1");
		T.near(2, s.get(P + "All|no_benchmark"), "all no benchmark");

		T.near(1, s.get(P + "Benchmark|SCG_7.0|objects"), "7.0 objects");
		T.near(3, s.get(P + "Benchmark|SCG_8.0|objects"), "8.0 objects");
		T.near(0, s.get(P + "Benchmark|SCG_9.0|objects"), "9.0 zero, pushed");
		T.near(4, s.get(P + "Benchmark|SCG_9.1|objects"), "9.1 objects");
		T.near(0, s.get(P + "Benchmark|SCG_6.7|objects"), "6.7 zero, pushed");
		T.near(2, s.get(P + "Benchmark|none|objects"), "none objects");
		T.check(!s.containsKey(P + "Benchmark|Custom|objects"),
				"Custom only when used");
		T.near(0, s.get(P + "Benchmark|unknown|objects"), "unknown pushed as 0");

		// Benchmark buckets add up to every object recorded.
		double objects = 0;
		for (String b : ComplianceRollup.FIXED_BUCKETS) {
			objects += s.get(P + "Benchmark|" + b + "|objects");
		}
		T.near(10, objects, "buckets sum to all objects");

		// Empty rollup: counts pushed as 0, no averages.
		Map<String, Double> e = new ComplianceRollup().toStats();
		T.near(0, e.get(P + "All|scored"), "empty scored");
		T.check(!e.containsKey(P + "All|avg_score"), "empty has no avg");

		// Custom profile bucket appears when used.
		ComplianceRollup c = new ComplianceRollup();
		c.recordEvaluated(BenchmarkSelector.Kind.HOST,
				BenchmarkSelector.bucketOf("Custom"), 1, 0, 0, 100.0);
		T.near(1, c.toStats().get(P + "Benchmark|Custom|objects"), "custom");

		// Review B2: version unreadable (no previous benchmark) is
		// non-compliant and in the unknown bucket, never no_benchmark.
		ComplianceRollup u = new ComplianceRollup();
		u.recordVersionUnreadable(BenchmarkSelector.Kind.HOST);
		Map<String, Double> us = u.toStats();
		T.near(1, us.get(P + "Host|non_compliant"), "unreadable version nc");
		T.near(0, us.get(P + "Host|no_benchmark"), "not no_benchmark");
		T.near(1, us.get(P + "Benchmark|unknown|objects"), "unknown bucket");
		T.near(0, us.get(P + "Benchmark|none|objects"), "not none bucket");
		T.check(!us.containsKey(P + "Host|avg_score"),
				"version-unreadable is not scored (unchanged in build 63)");

		T.check(ComplianceRollup.isNonCompliant(0, 1), "unreadable -> nc");
		T.check(ComplianceRollup.isNonCompliant(1, 0), "fail -> nc");
		T.check(!ComplianceRollup.isNonCompliant(0, 0), "clean -> compliant");

		System.out.println("ComplianceRollupTest: all assertions passed");
	}
}
