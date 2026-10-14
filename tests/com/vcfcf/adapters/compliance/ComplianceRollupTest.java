package com.vcfcf.adapters.compliance;

import java.util.Map;

/** Rollup arithmetic (build 57), including no_benchmark and unreadable. */
public final class ComplianceRollupTest {

	private static final String P = ComplianceRollup.PREFIX;

	public static void main(String[] args) {
		// Build 95 score rule (decision point 7, replaces build 63's):
		// passed over evaluated, over what was read; unreadable controls
		// are in neither count, so they no longer lower the score.
		T.near(90, ControlEvaluator.score(9, 1), "9/10");
		T.near(100, ControlEvaluator.score(8, 0),
				"8 read, 8 pass: 100 whatever was unreadable (was 80)");
		T.near(100, ControlEvaluator.score(0, 0),
				"nothing read: the zero-divisor placeholder, never pushed");
		T.near(80, ControlEvaluator.score(4, 1), "4 of 5 read");

		ComplianceRollup r = new ComplianceRollup();
		// Hosts: 90 (fails), 100 (clean), all-unreadable (0), partially
		// unreadable (80), and one no-benchmark (ESX 10.0).
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_8.0", 10, 1, 0,
				ControlEvaluator.score(9, 1));
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 10, 0, 0,
				ControlEvaluator.score(10, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 0, 0, 40,
				ControlEvaluator.score(0, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_7.0", 8, 0, 2,
				ControlEvaluator.score(8, 0));
		r.recordNoBenchmark(BenchmarkSelector.Kind.HOST);
		// VMs: one clean, one with an unreadable control.
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_8.0", 4, 0, 0,
				ControlEvaluator.score(4, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_8.0", 4, 0, 1,
				ControlEvaluator.score(4, 0));
		// vCenter scored 50; a non-vSAN cluster (nothing attempted).
		r.recordEvaluated(BenchmarkSelector.Kind.VCENTER, "SCG_9.1", 2, 1, 0,
				ControlEvaluator.score(1, 1));
		r.recordEvaluated(BenchmarkSelector.Kind.CLUSTER, "SCG_9.1", 0, 0, 0,
				ControlEvaluator.score(0, 0));
		// Portgroup with no benchmark; vDS nothing at all.
		r.recordNoBenchmark(BenchmarkSelector.Kind.PORTGROUP);

		Map<String, Double> s = r.toStats();

		// Build 95: counts come from what was read; the all-unreadable
		// host is not scored and not non-compliant, and the partly
		// unreadable host scores 100 over its 8 read controls and is not
		// non-compliant (has_unreadable on the objects carries both).
		T.near(3, s.get(P + "Host|scored"),
				"all-unreadable host is not scored (build 95)");
		T.near(290, s.get(P + "Host|score_sum"), "host sum 90+100+100");
		T.near(290.0 / 3, s.get(P + "Host|avg_score"), "host avg");
		T.near(1, s.get(P + "Host|non_compliant"),
				"host non-compliant: the failing host only");
		T.near(1, s.get(P + "Host|no_benchmark"), "host no benchmark");
		T.check(!s.containsKey(P + "Host|scored_stale"),
				"scored_stale retired in build 63");

		T.near(2, s.get(P + "VM|scored"), "vm scored");
		T.near(0, s.get(P + "VM|non_compliant"),
				"an unreadable control no longer makes a VM non-compliant");
		T.near(100, s.get(P + "VM|avg_score"), "vm avg (100 + 100) / 2");

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

		T.near(6, s.get(P + "All|scored"), "all scored 3+2+1");
		T.near(540, s.get(P + "All|score_sum"), "all sum 290+200+50");
		T.near(90, s.get(P + "All|avg_score"), "all weighted avg 540/6");
		T.near(2, s.get(P + "All|non_compliant"), "all non-compliant 1+0+1");
		T.near(2, s.get(P + "All|no_benchmark"), "all no benchmark");

		T.near(1, s.get(P + "Benchmark|SCG_7.0|objects"), "7.0 objects");
		T.near(3, s.get(P + "Benchmark|SCG_8.0|objects"), "8.0 objects");
		T.near(0, s.get(P + "Benchmark|SCG_9.0|objects"), "9.0 zero, pushed");
		T.near(4, s.get(P + "Benchmark|SCG_9.1|objects"), "9.1 objects");
		T.near(0, s.get(P + "Benchmark|SCG_6.7|objects"), "6.7 zero, pushed");
		T.near(2, s.get(P + "Benchmark|none|objects"), "none objects");
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

		// Review B2: version unreadable (no previous benchmark) is in the
		// unknown bucket, never no_benchmark. Build 95: nothing was read,
		// so that bucket is all it is counted in (not scored, not nc).
		ComplianceRollup u = new ComplianceRollup();
		u.recordVersionUnreadable(BenchmarkSelector.Kind.HOST);
		Map<String, Double> us = u.toStats();
		T.near(0, us.get(P + "Host|non_compliant"), "not counted nc");
		T.near(0, us.get(P + "Host|no_benchmark"), "not no_benchmark");
		T.near(1, us.get(P + "Benchmark|unknown|objects"), "unknown bucket");
		T.near(0, us.get(P + "Benchmark|none|objects"), "not none bucket");
		T.near(0, us.get(P + "Host|scored"), "version-unreadable not scored");
		T.near(0, us.get(P + "Host|score_sum"), "no score summed");
		T.check(!us.containsKey(P + "Host|avg_score"), "no avg, never 0");

		// Build 95: a failing control that was read; unreadable is not
		// non-compliance (builds 63 to 94 said it was).
		T.check(ComplianceRollup.isNonCompliant(1), "fail -> nc");
		T.check(!ComplianceRollup.isNonCompliant(0), "no failure -> compliant");

		build88Unmatched();
		build88Pods();
		build88DevelWorkedExample();
		build92RetiredCustom();
		build95PassRate();
		build95HeldBack();
		build95NothingEvaluated();
		build95ProdWorkedExample();

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
					ControlEvaluator.score(8, 2));
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
		double pod = ControlEvaluator.score(15, 4);
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

	/**
	 * Build 92 (review N2): an account stored as the removed Custom profile
	 * zeroes Benchmark|Custom|objects once, only on a complete rollup.
	 */
	static void build92RetiredCustom() {
		ComplianceRollup r = new ComplianceRollup();
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.0", 10, 0, 0,
				ControlEvaluator.score(10, 0));
		Map<String, Double> s = r.toStats();
		T.check(!s.containsKey(ComplianceRollup.RETIRED_CUSTOM_KEY),
				"no Custom bucket normally");
		T.check(ComplianceRollup.zeroRetiredCustom(s), "complete: added");
		T.near(0, s.get(ComplianceRollup.RETIRED_CUSTOM_KEY), "pushed as 0");
		T.eq(P + "Benchmark|Custom|objects",
				ComplianceRollup.RETIRED_CUSTOM_KEY, "the build 91 key");

		ComplianceRollup inc = new ComplianceRollup();
		inc.markIncomplete(BenchmarkSelector.Kind.VM);
		Map<String, Double> is = inc.toStats();
		T.check(!ComplianceRollup.zeroRetiredCustom(is),
				"incomplete: Benchmark keys held back, Custom not zeroed");
		T.check(!is.containsKey(ComplianceRollup.RETIRED_CUSTOM_KEY),
				"incomplete: no Custom key");
	}

	/**
	 * Build 95: a vCenter with a mix of kinds. Per kind and for All,
	 * pass_rate = controls_passed / controls_evaluated * 100; unreadable
	 * controls are in neither count and have no rollup key (build 95
	 * decision: each object carries has_unreadable instead).
	 */
	static void build95PassRate() {
		ComplianceRollup r = new ComplianceRollup();
		// Hosts: 9 of 10, 8 of 8 with 2 unreadable, all 40 unreadable.
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 10, 1, 0,
				ControlEvaluator.score(9, 1));
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 8, 0, 2,
				ControlEvaluator.score(8, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 0, 0, 40,
				ControlEvaluator.score(0, 0));
		// VMs: 15 of 19, twice.
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19, 4, 0,
				ControlEvaluator.score(15, 4));
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19, 4, 0,
				ControlEvaluator.score(15, 4));
		// vCenter: 15 of 20, 1 unreadable.
		r.recordEvaluated(BenchmarkSelector.Kind.VCENTER, "SCG_9.1", 20, 5, 1,
				ControlEvaluator.score(15, 5));
		// Non-vSAN cluster: nothing attempted. Port group: 12 of 12.
		r.recordEvaluated(BenchmarkSelector.Kind.CLUSTER, "SCG_9.1", 0, 0, 0,
				ControlEvaluator.score(0, 0));
		r.recordEvaluated(BenchmarkSelector.Kind.PORTGROUP, "SCG_9.1", 12, 0,
				0, ControlEvaluator.score(12, 0));
		// A no-benchmark host and a version-unreadable VM add no controls.
		r.recordNoBenchmark(BenchmarkSelector.Kind.HOST);
		r.recordVersionUnreadable(BenchmarkSelector.Kind.VM);
		Map<String, Double> s = r.toStats();

		T.near(18, s.get(P + "Host|controls_evaluated"), "host evaluated 10+8+0");
		T.near(17, s.get(P + "Host|controls_passed"), "host passed 9+8+0");
		T.near(1700.0 / 18, s.get(P + "Host|pass_rate"),
				"host pass_rate = passed / evaluated");
		T.near(38, s.get(P + "VM|controls_evaluated"), "vm evaluated");
		T.near(30, s.get(P + "VM|controls_passed"), "vm passed");
		T.near(3000.0 / 38, s.get(P + "VM|pass_rate"), "vm pass_rate");
		T.near(20, s.get(P + "vCenter|controls_evaluated"), "vc evaluated");
		T.near(15, s.get(P + "vCenter|controls_passed"), "vc passed");
		T.near(75, s.get(P + "vCenter|pass_rate"),
				"vc pass_rate 15/20, unreadable not in the denominator");
		T.near(100, s.get(P + "Portgroup|pass_rate"), "pg pass_rate");
		T.near(0, s.get(P + "Cluster|controls_evaluated"), "cluster none");
		T.check(!s.containsKey(P + "Cluster|pass_rate"),
				"cluster: nothing evaluated, no pass_rate");
		T.check(!s.containsKey(P + "vDS|pass_rate"), "vDS: no pass_rate");
		T.near(0, s.get(P + "vDS|controls_evaluated"), "vDS counts pushed 0");

		T.near(88, s.get(P + "All|controls_evaluated"), "all evaluated");
		T.near(74, s.get(P + "All|controls_passed"), "all passed");
		T.near(7400.0 / 88, s.get(P + "All|pass_rate"),
				"All pass_rate is the ratio of sums");
		// The object mean is unchanged and differs from the pass rate.
		double mean = s.get(P + "All|score_sum") / s.get(P + "All|scored");
		T.near(mean, s.get(P + "All|avg_score"), "avg_score still the mean");
		T.check(Math.abs(mean - s.get(P + "All|pass_rate")) > 0.5,
				"pass_rate is not the object mean");
		for (String key : s.keySet()) {
			T.check(!key.endsWith("|controls_unreadable"),
					"no unreadable rollup key: " + key);
		}
		// Per-kind sums add up to All.
		double ev = 0, pa = 0;
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			ev += s.get(P + k.rollupName + "|controls_evaluated");
			pa += s.get(P + k.rollupName + "|controls_passed");
		}
		T.near(88, ev, "kinds sum to All evaluated");
		T.near(74, pa, "kinds sum to All passed");
		T.check(ComplianceRollup.passRate(0, 0) == null, "passRate(0,0) null");
		T.near(50, ComplianceRollup.passRate(1, 2), "passRate(1,2)");
	}

	/**
	 * Build 95: a kind whose listing failed holds its control counts and
	 * pass_rate back with its other keys, and All's with it (build 78/88).
	 */
	static void build95HeldBack() {
		ComplianceRollup r = new ComplianceRollup();
		r.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 10, 1, 0,
				ControlEvaluator.score(9, 1));
		r.recordEvaluated(BenchmarkSelector.Kind.VM, "SCG_9.1", 19, 4, 0,
				ControlEvaluator.score(15, 4));
		r.markIncomplete(BenchmarkSelector.Kind.VM);
		Map<String, Double> s = r.toStats();
		for (String k : new String[] {"controls_evaluated", "controls_passed",
				"pass_rate"}) {
			T.check(!s.containsKey(P + "VM|" + k), "VM|" + k + " held back");
			T.check(!s.containsKey(P + "All|" + k), "All|" + k + " held back");
		}
		T.near(10, s.get(P + "Host|controls_evaluated"),
				"other kinds still pushed");
		T.near(90, s.get(P + "Host|pass_rate"), "host pass_rate pushed");
		T.near(1, s.get(ComplianceRollup.INCOMPLETE_KEY), "incomplete = 1");
	}

	/**
	 * Build 95: nothing evaluated means no pass_rate (never 100), with the
	 * counts still pushed; all-unreadable controls are neither counted nor
	 * passed, and the object is not scored (build 95).
	 */
	static void build95NothingEvaluated() {
		Map<String, Double> e = new ComplianceRollup().toStats();
		T.near(0, e.get(P + "All|controls_evaluated"), "empty evaluated 0");
		T.near(0, e.get(P + "All|controls_passed"), "empty passed 0");
		T.check(!e.containsKey(P + "All|controls_unreadable"),
				"no unreadable rollup key (build 95 decision)");
		T.check(!e.containsKey(P + "All|pass_rate"), "empty: no pass_rate");
		for (BenchmarkSelector.Kind k : BenchmarkSelector.Kind.values()) {
			T.check(!e.containsKey(P + k.rollupName + "|pass_rate"),
					"empty: no " + k.rollupName + "|pass_rate");
		}

		ComplianceRollup u = new ComplianceRollup();
		u.recordEvaluated(BenchmarkSelector.Kind.HOST, "SCG_9.1", 0, 0, 40,
				ControlEvaluator.score(0, 0));
		u.recordVersionUnreadable(BenchmarkSelector.Kind.VM);
		Map<String, Double> us = u.toStats();
		T.near(0, us.get(P + "Host|controls_evaluated"), "unreadable: 0 eval");
		T.near(0, us.get(P + "Host|scored"), "all unreadable: not scored");
		T.near(0, us.get(P + "Host|non_compliant"), "all unreadable: not nc");
		T.check(!us.containsKey(P + "Host|controls_unreadable"),
				"no unreadable rollup key");
		T.check(!us.containsKey(P + "Host|pass_rate"),
				"all unreadable: no pass_rate, never 100");
		T.check(!us.containsKey(P + "All|pass_rate"), "All: no pass_rate");
		T.check(!us.containsKey(P + "All|avg_score"),
				"nothing read: no object mean either (build 95)");
	}

	/**
	 * Build 95 worked example: the prod table of 2026-10-14 (scored
	 * objects and object-mean scores per vCenter and kind), with a FIXED
	 * evaluated-control count per kind (the SCG 9.1 evaluable controls:
	 * host 56, VM 22, vCenter 10, cluster 2, vDS 7, port group 7) and no
	 * unreadable controls, so each kind's per-object mean is passed /
	 * evaluated. Passed per vCenter and kind is round(mean * count *
	 * objects), spread over the objects. Environment = the ComputedMetric
	 * ratio of the vCenters' All sums. Prod object-weighted mean: 79.87.
	 */
	@SuppressWarnings("unchecked")
	static void build95ProdWorkedExample() {
		BenchmarkSelector.Kind[] kinds = {BenchmarkSelector.Kind.HOST,
				BenchmarkSelector.Kind.VM, BenchmarkSelector.Kind.CLUSTER,
				BenchmarkSelector.Kind.VCENTER, BenchmarkSelector.Kind.VDS,
				BenchmarkSelector.Kind.PORTGROUP};
		int[] controls = {56, 22, 2, 10, 7, 7};
		int[][] objects = {{6, 2, 2}, {46, 25, 32}, {1, 0, 0}, {1, 1, 1},
				{1, 1, 1}, {12, 32, 14}};
		double[][] means = {{65.28, 72.92, 71.88}, {74.41, 73.64, 74.43},
				{100, 0, 0}, {50, 50, 50}, {75, 75, 75},
				{90.48, 95.54, 90.82}};
		ComplianceRollup[] vc = {new ComplianceRollup(),
				new ComplianceRollup(), new ComplianceRollup()};
		long[] kindPassed = new long[kinds.length];
		long[] kindEval = new long[kinds.length];
		for (int k = 0; k < kinds.length; k++) {
			for (int v = 0; v < 3; v++) {
				int n = objects[k][v];
				if (n == 0) continue;
				int c = controls[k];
				long passed = Math.round(means[k][v] / 100.0 * c * n);
				for (int i = 0; i < n; i++) {
					int p = (int) (passed / n + (i < passed % n ? 1 : 0));
					vc[v].recordEvaluated(kinds[k], "SCG_9.1", c, c - p, 0,
							ControlEvaluator.score(p, c - p));
				}
				kindPassed[k] += passed;
				kindEval[k] += (long) c * n;
			}
		}
		Map<String, Double>[] st = new Map[3];
		for (int v = 0; v < 3; v++) st[v] = vc[v].toStats();
		double envPassed = 0, envEval = 0, envScored = 0, envSum = 0;
		for (int v = 0; v < 3; v++) {
			envPassed += st[v].get(P + "All|controls_passed");
			envEval += st[v].get(P + "All|controls_evaluated");
			envScored += st[v].get(P + "All|scored");
			envSum += st[v].get(P + "All|score_sum");
		}
		T.near(178, envScored, "prod objects scored");
		// Whole controls per object round the means slightly (a vDS
		// cannot pass 75% of 7), so the mean lands within 0.1 of prod.
		T.check(Math.abs(79.87 - envSum / envScored) < 0.1,
				"object-weighted mean reproduces prod 79.87: "
				+ envSum / envScored);
		for (int k = 0; k < kinds.length; k++) {
			double sumP = 0, sumE = 0;
			for (int v = 0; v < 3; v++) {
				String n = kinds[k].rollupName;
				sumP += st[v].get(P + n + "|controls_passed");
				sumE += st[v].get(P + n + "|controls_evaluated");
			}
			T.near((double) kindPassed[k], sumP, kinds[k] + " passed");
			T.near((double) kindEval[k], sumE, kinds[k] + " evaluated");
		}
		double env = envPassed / envEval * 100.0;
		// Pinned: 2475 of 3285 controls pass (75.34%), below the 79.87
		// object mean: a host's 56 controls now weigh 8 times a port
		// group's 7, and the 58 port groups no longer carry the number.
		T.near(3285, envEval, "environment controls evaluated");
		T.near(2475, envPassed, "environment controls passed");
		T.near(247500.0 / 3285, env, "environment pass_rate");
		if (Boolean.getBoolean("rollup.print")) {
			for (int k = 0; k < kinds.length; k++) {
				System.out.printf("%s passed %d / evaluated %d = %.2f%%%n",
						kinds[k].rollupName, kindPassed[k], kindEval[k],
						100.0 * kindPassed[k] / kindEval[k]);
			}
			for (int v = 0; v < 3; v++) {
				System.out.printf("vCenter %d All pass_rate %.2f (%s/%s)%n",
						v + 1, st[v].get(P + "All|pass_rate"),
						st[v].get(P + "All|controls_passed"),
						st[v].get(P + "All|controls_evaluated"));
			}
			System.out.printf("Environment pass_rate %.2f (%.0f/%.0f), "
					+ "object mean %.2f%n", env, envPassed, envEval,
					envSum / envScored);
		}
	}
}
