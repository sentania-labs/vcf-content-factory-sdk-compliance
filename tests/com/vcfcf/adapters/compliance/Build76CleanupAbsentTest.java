package com.vcfcf.adapters.compliance;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Build 76 (review of build 75): cleanup based on what was pushed this
 * cycle (not-applicable controls retire a lingering 0 or 1), and the VAMI
 * absent-default option. Run from the repo root.
 */
public final class Build76CleanupAbsentTest {

	public static void main(String[] args) {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkProfile p91 = all.get("VMware_SCG_9.1");
		BenchmarkSelector.Kind CL = BenchmarkSelector.Kind.CLUSTER;
		String mdc = "cluster.managed-disk-claim";
		T.check(BenchmarkSelector.evaluatedFor(CL,
				ProfileSetTest.find(p91.controls, mdc)), "fixture: scored in 9.1");

		// Non-vSAN cluster: vSAN gate says not applicable, nothing pushed.
		ComplianceDecisions.CleanupPlan nonVsan = ComplianceDecisions.cleanupPlan(
				CL, p91, new TreeSet<String>(), all.values());
		T.check(nonVsan.zeroOrOne.contains(mdc),
				"in-benchmark, not pushed: retire 0 or 1");
		Map<String, Double> stale1 = new HashMap<>();
		stale1.put(mdc, 1.0);                    // the old false pass
		T.eq(java.util.Collections.singleton(mdc),
				ComplianceDecisions.staleControls(nonVsan, stale1),
				"non-vSAN cluster: stale 1 goes to -1");
		Map<String, Double> stale0 = new HashMap<>();
		stale0.put(mdc, 0.0);                    // an alert that never closed
		T.eq(java.util.Collections.singleton(mdc),
				ComplianceDecisions.staleControls(nonVsan, stale0),
				"non-vSAN cluster: stale 0 goes to -1");
		Map<String, Double> already = new HashMap<>();
		already.put(mdc, -1.0);
		T.check(ComplianceDecisions.staleControls(nonVsan, already).isEmpty(),
				"already -1: untouched");
		T.check(ComplianceDecisions.staleControls(nonVsan, null).isEmpty(),
				"failed read-back changes nothing");
		T.check(ComplianceDecisions.staleControls(nonVsan, new HashMap<>())
				.isEmpty(), "key absent: never created");

		// vSAN cluster: the control was pushed this cycle: untouched.
		ComplianceDecisions.CleanupPlan vsan = ComplianceDecisions.cleanupPlan(
				CL, p91, new TreeSet<>(Arrays.asList(mdc)), all.values());
		T.check(!vsan.zeroOrOne.contains(mdc) && !vsan.zeroOnly.contains(mdc),
				"pushed live: not a candidate");
		T.check(ComplianceDecisions.staleControls(vsan, stale1).isEmpty()
				&& ComplianceDecisions.staleControls(vsan, stale0).isEmpty(),
				"vSAN cluster untouched");

		// Controls OUTSIDE the benchmark keep the 0-only rule.
		BenchmarkSelector.Kind VDS = BenchmarkSelector.Kind.VDS;
		ComplianceDecisions.CleanupPlan dvs = ComplianceDecisions.cleanupPlan(
				VDS, p91, new TreeSet<String>(), all.values());
		String outside = "vds.network-reset-port";   // retired id, never in 9.1
		T.check(dvs.zeroOnly.contains(outside), "outside: 0-only");
		Map<String, Double> one = new HashMap<>();
		one.put(outside, 1.0);
		T.check(ComplianceDecisions.staleControls(dvs, one).isEmpty(),
				"outside the benchmark: a 1 is left alone");
		Map<String, Double> zero = new HashMap<>();
		zero.put(outside, 0.0);
		T.eq(java.util.Collections.singleton(outside),
				ComplianceDecisions.staleControls(dvs, zero),
				"outside the benchmark: a 0 goes to -1");

		// pushedIds reads the pushed results.
		ControlEvaluator.ComplianceResult cr = new ControlEvaluator.ComplianceResult(
				"h", 1, 0, 1, 1, 50.0, Arrays.asList(
						new ControlEvaluator.ControlResult("a.x", "1", "1", true, "d"),
						new ControlEvaluator.ControlResult("a.y", "(unreadable)",
								"1", false, "d", true)));
		T.eq(new TreeSet<>(Arrays.asList("a.x", "a.y")),
				ComplianceDecisions.pushedIds(cr),
				"unreadable results are pushed (-1) too");

		// ---- VAMI absent default
		VamiRecipe r = VamiRecipe.parse(
				"vami:local-accounts/root:max_days_between_password_change?absent=-1");
		T.eq("local-accounts/root", r.appliancePath, "path");
		T.eq("max_days_between_password_change", r.field, "field without option");
		T.eq("-1", r.absentDefault, "absent default");
		T.eq("-1", r.absentValue(true),
				"absent field in a successful object body -> -1 (never expires)");
		T.eq(null, r.absentValue(false),
				"body not a JSON object -> unreadable");
		VamiRecipe plain = VamiRecipe.parse("vami:ntp:(list)");
		T.eq(null, plain.absentDefault, "no option by default");
		T.eq(null, plain.absentValue(true), "no default -> unreadable");
		T.eq(null, VamiRecipe.parse("vami:x:(value)?absent=1"),
				"absent option only on named fields");
		T.eq(null, VamiRecipe.parse("vami:x:field?absent="), "empty default");
		// Present and absent both score against the SCG's -1 expected value.
		BenchmarkProfile.Control pw = ProfileSetTest.find(p91.controls,
				"vc.vami-password-max-age");
		T.check(ControlEvaluator.vimPropertyMatches(r.absentValue(true),
				pw.expectedValue), "absent (never expires) passes -1");
		T.check(ControlEvaluator.vimPropertyMatches("-1", pw.expectedValue),
				"present -1 passes");
		T.check(!ControlEvaluator.vimPropertyMatches("90", pw.expectedValue),
				"present 90 fails");
		// Every root-password row in every profile carries the option.
		for (BenchmarkProfile p : all.values()) {
			for (String id : new String[] {"vc.vami-password-max-age",
					"vc.vami-administration-password-expiration"}) {
				BenchmarkProfile.Control c = ProfileSetTest.find(p.controls, id);
				if (c != null) T.check(c.readRecipe.endsWith("?absent=-1"),
						p.name + " " + id);
			}
		}

		System.out.println("Build76CleanupAbsentTest: all assertions passed");
	}
}
