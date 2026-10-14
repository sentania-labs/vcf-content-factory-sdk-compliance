package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Build 95, Scott's decision 2026-10-14 ("if we have missing data we just
 * don't log it - but flag the stale metric, and then that becomes an
 * alarm"): unreadable data is skipped and flagged per object. Each method
 * pins one point of the decision on the SDK-free classes the adapter
 * runs. Run from the repo root.
 */
public final class Build95UnreadableTest {

	private static final String K = "VCF-CF Compliance|";

	public static void main(String[] args) throws Exception {
		unreadableNotPushed();
		System.out.println("Build95UnreadableTest: all assertions passed");
	}

	/** Two read controls (one pass, one fail) and one unreadable. */
	static ControlEvaluator.ComplianceResult mixed() {
		List<ControlEvaluator.ControlResult> r = new ArrayList<>();
		r.add(new ControlEvaluator.ControlResult("esx.a", "1", "1", true, "da"));
		r.add(new ControlEvaluator.ControlResult("esx.b", "0", "1", false, "db"));
		r.add(new ControlEvaluator.ControlResult("esx.c", "(unreadable)", "1",
				false, "dc", true));
		return new ControlEvaluator.ComplianceResult("h", 1, 1, 2, 1,
				ControlEvaluator.score(1, 1, 1), r);
	}

	/**
	 * The result the adapter builds for a host vCenter reports
	 * notResponding (wholeUnreadable): every advanced_setting and every
	 * vim / esxcli control of the benchmark folded to UNREADABLE.
	 */
	static List<ControlEvaluator.ComplianceResult> notResponding(
			List<BenchmarkProfile.Control> hostControls) {
		ControlEvaluator.ComplianceResult adv =
				ControlEvaluator.evaluateControlsUnreadable(hostControls, "h");
		Map<String, Object> values = new HashMap<>();
		for (BenchmarkProfile.Control c : hostControls) {
			if (("vim_property".equals(c.parameterKind)
					|| "esxcli".equals(c.parameterKind)) && c.isEvaluable()) {
				values.put(c.configParameter, VSphereClient.UNREADABLE);
			}
		}
		ControlEvaluator.ComplianceResult vim =
				ControlEvaluator.evaluateVimProperties(hostControls, values,
						"h", VSphereClient.UNREADABLE);
		return Arrays.asList(adv, vim);
	}

	/**
	 * Point 1: an unreadable control is not pushed (no -1, no
	 * "(unreadable)" Actual), for every cause, including a host vCenter
	 * reports notResponding; the stale-key cleanup leaves it alone and the
	 * Skip push is unchanged.
	 */
	static void unreadableNotPushed() {
		ControlEvaluator.ComplianceResult cr = mixed();
		Map<String, Double> stats = ComplianceDecisions.complianceStats(cr);
		T.near(1, stats.get(K + "esx.a|Compliant"), "read pass pushed");
		T.near(0, stats.get(K + "esx.b|Compliant"), "read fail pushed");
		T.check(!stats.containsKey(K + "esx.c|Compliant"),
				"unreadable control: no Compliant value (no -1)");
		Map<String, String> props = ComplianceDecisions.complianceProps(cr,
				"VMware_SCG_9.1", new java.util.TreeSet<>(
						Arrays.asList("esx.c")));
		T.eq("1", props.get(K + "esx.a|Actual"), "read Actual pushed");
		for (String f : new String[] {"Actual", "Expected", "Description"}) {
			T.check(!props.containsKey(K + "esx.c|" + f),
					"unreadable control: no " + f + " overwrite");
		}
		for (String v : props.values()) {
			T.check(v == null || !v.contains("(unreadable)"),
					"no (unreadable) text: " + v);
		}

		// A host vCenter reports notResponding: nothing per control.
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkProfile p91 = all.get("VMware_SCG_9.1");
		List<ControlEvaluator.ComplianceResult> nr =
				notResponding(p91.hostControls());
		ControlEvaluator.ComplianceResult adv = nr.get(0);
		T.check(nr.get(0).unreadableCount > 0 && nr.get(1).unreadableCount > 0,
				"both channels unreadable");
		for (ControlEvaluator.ComplianceResult u : nr) {
			for (String key : ComplianceDecisions.complianceStats(u).keySet()) {
				T.check(!key.endsWith("|Compliant"),
						"notResponding host: no per-control push: " + key);
			}
			for (String key : ComplianceDecisions.complianceProps(u,
					"VMware_SCG_9.1").keySet()) {
				T.check(!key.endsWith("|Actual"),
						"notResponding host: no Actual push: " + key);
			}
		}

		// The stale-key cleanup: an unreadable control of the current
		// benchmark is in the held set, so it is never retired to -1 (its
		// last 0 or 1, and any alert on it, stay).
		String unread = adv.controlResults.get(0).scgId;
		Set<String> held = ComplianceDecisions.pushedIds(adv);
		T.check(held.contains(unread), "unreadable control is held");
		ComplianceDecisions.CleanupPlan plan = ComplianceDecisions.cleanupPlan(
				BenchmarkSelector.Kind.HOST, p91, held, all.values(),
				java.util.Collections.<String>emptySet());
		T.check(!plan.zeroOrOne.contains(unread)
				&& !plan.zeroOnly.contains(unread),
				"cleanup does not plan to retire an unreadable control");
		Map<String, Double> lastValues = new HashMap<>();
		lastValues.put(unread, 1.0);
		T.check(ComplianceDecisions.staleControls(plan, lastValues).isEmpty(),
				"its last 1 stays");
		lastValues.put(unread, 0.0);
		T.check(ComplianceDecisions.staleControls(plan, lastValues).isEmpty(),
				"its last 0 (and alert) stays");

		// The Skip push is unchanged: -1 and the skip text, every cycle.
		ComplianceDecisions.SkipPush skip = ComplianceDecisions.skipPush(
				BenchmarkSelector.Kind.HOST, p91,
				new java.util.TreeSet<>(Arrays.asList(unread)), "ovr");
		T.near(-1, skip.stats.get(K + unread + "|Compliant"), "skip still -1");
		T.check(skip.props.get(K + unread + "|Actual")
				.contains("skipped by override file ovr"), "skip text");
	}
}
