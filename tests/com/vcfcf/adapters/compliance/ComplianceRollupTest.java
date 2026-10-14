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
		// unreadable (80), and one no-benchmark (ESX 10.0).
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
		// Build 65 (W1): nothing collected -> scored with 0.
		T.near(1, us.get(P + "Host|scored"), "version-unreadable is scored");
		T.near(0, us.get(P + "Host|score_sum"), "with score 0");
		T.near(0, us.get(P + "Host|avg_score"), "avg 0");

		T.check(ComplianceRollup.isNonCompliant(0, 1), "unreadable -> nc");
		T.check(ComplianceRollup.isNonCompliant(1, 0), "fail -> nc");
		T.check(!ComplianceRollup.isNonCompliant(0, 0), "clean -> compliant");

		build88Unmatched();
		build88Pods();
		build88DevelWorkedExample();

		System.out.println("ComplianceRollupTest: all assertions passed");
	}

	/**
	 * Build 88: an object with no VCF Ops resource is in Rollup|<K>|unmatched
	 * and nowhere else, for every kind; the key is pushed as 0 on a clean
	 * cycle; All carries no unmatched key.
	 */
	private static void build88Unmatched() {
		// Clean cycle: every kind's unmatched pushed as 0, skipped_pods 0.
		Map<String, Double> clean = new ComplianceRollup().toStats();
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			T.near(0, clean.get(P + k.rollupName + "|unmatched"),
					k.rollupName + "|unmatched pushed as 0 on a clean cycle");
		}
		T.near(0, clean.get(P + "VM|skipped_pods"),
				"VM|skipped_pods pushed as 0 on a clean cycle");
		T.check(!clean.containsKey(P + "All|unmatched"),
				"no All|unmatched (per-kind key only)");
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			if (k != BenchmarkSelector.Kind.VM) {
				T.check(!clean.containsKey(P + k.rollupName + "|skipped_pods"),
						"skipped_pods only on VM, not " + k.rollupName);
			}
		}

		// Per kind: one scored (non-compliant) object, two unmatched.
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			ComplianceRollup r = new ComplianceRollup();
			r.recordEvaluated(k, "SCG_9.1", 10, 2, 0,
					ControlEvaluator.score(8, 2, 0));
			r.recordUnmatched(k, "a-" + k.rollupName, "moid-1");
			r.recordUnmatched(k, "b-" + k.rollupName, "moid-2");
			Map<String, Double> s = r.toStats();
			String n = k.rollupName;
			T.near(2, s.get(P + n + "|unmatched"), n + " unmatched counted");
			T.near(1, s.get(P + n + "|scored"), n + " unmatched not scored");
			T.near(1, s.get(P + n + "|non_compliant"),
					n + " unmatched not non-compliant");
			T.near(0, s.get(P + n + "|no_benchmark"),
					n + " unmatched not no_benchmark");
			T.near(80, s.get(P + n + "|score_sum"), n + " score_sum");
			T.near(1, s.get(P + "All|scored"), n + ": All excludes unmatched");
			T.near(1, s.get(P + "All|non_compliant"), n + ": All nc");
			T.near(0, s.get(P + "All|no_benchmark"), n + ": All nb");
			T.near(1, s.get(P + "Benchmark|SCG_9.1|objects"),
					n + ": unmatched in no benchmark bucket");
			double objects = 0;
			for (String b : ComplianceRollup.FIXED_BUCKETS) {
				objects += s.get(P + "Benchmark|" + b + "|objects");
			}
			T.near(1, objects, n + ": buckets count only matched objects");
			for (BenchmarkSelector.Kind o : BenchmarkSelector.Kind.values()) {
				if (o != k) {
					T.near(0, s.get(P + o.rollupName + "|unmatched"),
							n + ": unmatched stays on its own kind ("
							+ o.rollupName + ")");
				}
			}
			T.eq(2, r.unmatched(k), n + " unmatched()");
		}

		// The INFO line: null when none; names and MOIDs; capped.
		ComplianceRollup r = new ComplianceRollup();
		T.check(r.unmatchedLogLine(BenchmarkSelector.Kind.HOST) == null,
				"no line when nothing is unmatched");
		r.recordUnmatched(BenchmarkSelector.Kind.HOST, "esx09.lab", "host-99");
		String line = r.unmatchedLogLine(BenchmarkSelector.Kind.HOST);
		T.check(line != null && line.contains("esx09.lab (host-99)")
				&& line.startsWith("Host: 1 object(s)")
				&& line.contains("Rollup|Host|unmatched")
				&& !line.contains("more)"), "one unmatched host named: " + line);
		ComplianceRollup big = new ComplianceRollup();
		int cap = ComplianceRollup.UNMATCHED_LOG_CAP;
		for (int i = 0; i < cap + 5; i++) {
			big.recordUnmatched(BenchmarkSelector.Kind.VM, "vm" + i, "vm-" + i);
		}
		String bl = big.unmatchedLogLine(BenchmarkSelector.Kind.VM);
		T.check(bl.contains("vm" + (cap - 1) + " (vm-" + (cap - 1) + ")"),
				"last name inside the cap is listed");
		T.check(!bl.contains("vm" + cap + " (vm-" + cap + ")"),
				"first name past the cap is not listed");
		T.check(bl.endsWith(" (+5 more)"), "overflow counted: " + bl);
		T.near(cap + 5, big.toStats().get(P + "VM|unmatched"),
				"the count is not capped");
		ComplianceRollup nul = new ComplianceRollup();
		nul.recordUnmatched(BenchmarkSelector.Kind.VDS, null, null);
		T.check(nul.unmatchedLogLine(BenchmarkSelector.Kind.VDS)
				.contains("(no name) (no MOID)"), "null name and MOID labelled");

		// Incomplete kind: unmatched (and skipped_pods for VM) held back with
		// the kind's other keys, never pushed as a 0 the adapter did not take.
		ComplianceRollup inc = new ComplianceRollup();
		inc.recordUnmatched(BenchmarkSelector.Kind.VM, "x", "vm-1");
		inc.recordSkippedPod();
		inc.markIncomplete(BenchmarkSelector.Kind.VM);
		Map<String, Double> is = inc.toStats();
		T.check(!is.containsKey(P + "VM|unmatched"), "VM unmatched held back");
		T.check(!is.containsKey(P + "VM|skipped_pods"),
				"VM skipped_pods held back");
		T.near(1, is.get(ComplianceRollup.INCOMPLETE_KEY), "incomplete = 1");
		T.near(0, is.get(P + "Host|unmatched"),
				"other kinds still pushed (Host unmatched 0)");
	}

	/**
	 * Build 88: Pod VMs are counted in VM|skipped_pods only: not scored, not
	 * unmatched, not in All or any Benchmark bucket.
	 */
	private static void build88Pods() {
		ComplianceRollup r = new ComplianceRollup();
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19, 0, 0,
				100.0);
		for (int i = 0; i < 3; i++) {
			r.recordSkippedPod();
		}
		Map<String, Double> s = r.toStats();
		T.near(3, s.get(P + "VM|skipped_pods"), "pods counted");
		T.near(1, s.get(P + "VM|scored"), "pods not scored");
		T.near(0, s.get(P + "VM|non_compliant"), "pods not non-compliant");
		T.near(0, s.get(P + "VM|unmatched"), "pods are not unmatched");
		T.near(1, s.get(P + "All|scored"), "pods not in All");
		T.near(100, s.get(P + "All|avg_score"), "pods not in the average");
		T.near(1, s.get(P + "Benchmark|SCG_9.1|objects"),
				"pods in no benchmark bucket");
		T.near(0, s.get(P + "Benchmark|none|objects"), "nor in none");
		T.eq(3, r.skippedPods(), "skippedPods()");
	}

	/**
	 * Build 88 worked example, the devel numbers from the factory's
	 * knowledge/designs/sdk-adapters/compliance-rollup-unmatched-and-pod-skip.md:
	 * wld01's vCenter lists 43 VMs, 18 of them vSphere Pods (each scored
	 * 78.947 = 15 of 19 by build 87, so non-compliant). Build 87 scored all
	 * 43; build 88 scores the 25 VMs Ops has. Environment: Objects Scored
	 * 193 -> 175, Non-Compliant 158 -> 140. The split of the other objects
	 * across vCenters and kinds is synthetic (only the totals are from
	 * devel); the Pod effect on wld01 is exact.
	 */
	private static void build88DevelWorkedExample() {
		double pod = ControlEvaluator.score(15, 4, 0);
		T.near(1500.0 / 19, pod, "a Pod scored 78.947 under build 87");

		// wld01, build 88: 25 real VMs (synthetic: 20 non-compliant), 18 Pods
		// skipped, every object matched.
		ComplianceRollup wld01 = new ComplianceRollup();
		for (int i = 0; i < 25; i++) {
			boolean fails = i < 20;
			wld01.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19,
					fails ? 4 : 0, 0, fails ? pod : 100.0);
		}
		for (int i = 0; i < 18; i++) {
			wld01.recordSkippedPod();
		}
		// The same vCenter under build 87: the 18 Pods were scored as VMs.
		ComplianceRollup wld01b87 = new ComplianceRollup();
		for (int i = 0; i < 25; i++) {
			boolean fails = i < 20;
			wld01b87.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19,
					fails ? 4 : 0, 0, fails ? pod : 100.0);
		}
		for (int i = 0; i < 18; i++) {
			wld01b87.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19,
					4, 0, pod);
		}
		// Everything else in the environment (synthetic split, real totals):
		// 175 - 25 = 150 scored, 140 - 20 = 120 non-compliant.
		ComplianceRollup rest = new ComplianceRollup();
		for (int i = 0; i < 150; i++) {
			rest.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 10,
					i < 120 ? 1 : 0, 0, i < 120 ? 90.0 : 100.0);
		}

		Map<String, Double> w = wld01.toStats();
		Map<String, Double> w87 = wld01b87.toStats();
		Map<String, Double> o = rest.toStats();
		T.near(43, w87.get(P + "VM|scored"), "build 87: wld01 VM scored 43");
		T.near(25, w.get(P + "VM|scored"), "build 88: wld01 VM scored 25");
		T.near(18, w.get(P + "VM|skipped_pods"), "wld01 skipped_pods 18");
		T.near(0, o.get(P + "VM|skipped_pods"), "skipped_pods 0 elsewhere");
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			T.near(0, w.get(P + k.rollupName + "|unmatched"),
					"wld01 " + k.rollupName + "|unmatched 0");
			T.near(0, o.get(P + k.rollupName + "|unmatched"),
					"elsewhere " + k.rollupName + "|unmatched 0");
		}
		// The ComplianceWorld Rollup|Environment sums of Rollup|All.
		T.near(193, w87.get(P + "All|scored") + o.get(P + "All|scored"),
				"build 87 environment Objects Scored 193");
		T.near(158, w87.get(P + "All|non_compliant")
				+ o.get(P + "All|non_compliant"),
				"build 87 environment Non-Compliant 158");
		T.near(175, w.get(P + "All|scored") + o.get(P + "All|scored"),
				"build 88 environment Objects Scored 175");
		T.near(140, w.get(P + "All|non_compliant")
				+ o.get(P + "All|non_compliant"),
				"build 88 environment Non-Compliant 140");
	}
}
