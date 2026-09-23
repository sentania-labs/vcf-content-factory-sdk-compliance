package com.vcfcf.adapters.compliance;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Simulated mixed-version vCenter (owner-approved approach: fake the
 * inventory in tests; the lab runs one ESXi build).
 *
 * <p>Inventory: vCenter 9.1.1; hosts on ESXi 6.7, 7.0, 8.0 U3, 9.0, 9.1 and
 * an unmapped 10.0; VMs on the 6.7, 8.0 U3 and 10.0 hosts; one vDS that
 * reports its own version 9.0.0 (ignored) and one portgroup. The 9.1 host
 * is disconnected this cycle (whole-host unreadable) with a last-known
 * score; the 8.0 host fails one control.
 *
 * <p>Uses the REAL bundled profiles, {@link BenchmarkSelector},
 * {@link ControlEvaluator} and {@link ComplianceRollup}, driven the same way
 * {@code ComplianceAdapter} drives them (select, evaluate the kind slice,
 * record). The adapter class itself needs the VCF Ops SDK on the classpath,
 * so its collect loop is mirrored here, not invoked.
 */
public final class MixedVersionSimulationTest {

	private static final String P = ComplianceRollup.PREFIX;

	public static void main(String[] args) {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkSelector sel = BenchmarkSelector.auto(all);
		ComplianceRollup rollup = new ComplianceRollup();
		String vcVersion = "9.1.1";

		Map<String, String> hostVersion = new LinkedHashMap<>();
		hostVersion.put("host-67", "6.7.0");
		hostVersion.put("host-70", "7.0.3");
		hostVersion.put("host-80", "8.0.3");   // 8.0 U3
		hostVersion.put("host-90", "9.0.0");
		hostVersion.put("host-91", "9.1.1");
		hostVersion.put("host-100", "10.0.0");

		Map<String, String> profileByObject = new HashMap<>();

		// ---- hosts
		for (Map.Entry<String, String> h : hostVersion.entrySet()) {
			BenchmarkSelector.Selection s = sel.select(
					BenchmarkSelector.Kind.HOST,
					BenchmarkSelector.governingVersion(
							BenchmarkSelector.Kind.HOST, vcVersion,
							h.getValue()));
			profileByObject.put(h.getKey(), s.profileName);
			if (s.noBenchmark()) {
				rollup.recordNoBenchmark(BenchmarkSelector.Kind.HOST);
				continue;
			}
			List<BenchmarkProfile.Control> slice = s.profile.hostControls();
			ControlEvaluator.ComplianceResult cr;
			if (h.getKey().equals("host-91")) {
				// Disconnected: every control unreadable, no score.
				cr = merge(ControlEvaluator.evaluateControlsUnreadable(slice,
						h.getKey()), unreadableVim(slice, h.getKey()));
				T.eq(0, cr.totalCount, "disconnected host not scored");
				T.check(cr.unreadableCount > 0, "disconnected host unreadable");
				rollup.recordEvaluated(BenchmarkSelector.Kind.HOST, s.bucket,
						cr.totalCount, cr.failCount, cr.unreadableCount,
						cr.score);
				rollup.recordStaleScore(BenchmarkSelector.Kind.HOST, 50.0);
				continue;
			}
			Map<String, String> adv = passingSettings(slice);
			if (h.getKey().equals("host-80")) {
				// One deliberate failure: account lockout set too high.
				adv.put("Security.AccountLockFailures", "99");
			}
			cr = ControlEvaluator.evaluateControls(slice, adv, h.getKey());
			T.check(cr.totalCount > 0, h.getKey() + " scored something");
			if (h.getKey().equals("host-80")) {
				T.eq(1, cr.failCount, "8.0 host fails exactly one control");
			} else {
				T.eq(0, cr.failCount, h.getKey() + " no failures");
			}
			rollup.recordEvaluated(BenchmarkSelector.Kind.HOST, s.bucket,
					cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);
		}
		T.eq("VMware_SCG_6.7", profileByObject.get("host-67"), "6.7 host");
		T.eq("VMware_SCG_7.0", profileByObject.get("host-70"), "7.0 host");
		T.eq("VMware_SCG_8.0", profileByObject.get("host-80"), "8.0 U3 host");
		T.eq("VMware_SCG_9.0", profileByObject.get("host-90"), "9.0 host");
		T.eq("VMware_SCG_9.1", profileByObject.get("host-91"), "9.1 host");
		T.eq("no benchmark for ESXi 10.0", profileByObject.get("host-100"),
				"10.0 host");

		// ---- VMs follow their host
		Map<String, String> vmHost = new LinkedHashMap<>();
		vmHost.put("vm-a", "host-80");
		vmHost.put("vm-b", "host-100");
		vmHost.put("vm-c", "host-67");
		for (Map.Entry<String, String> v : vmHost.entrySet()) {
			BenchmarkSelector.Selection s = sel.select(BenchmarkSelector.Kind.VM,
					BenchmarkSelector.governingVersion(BenchmarkSelector.Kind.VM,
							vcVersion, hostVersion.get(v.getValue())));
			profileByObject.put(v.getKey(), s.profileName);
			if (s.noBenchmark()) {
				rollup.recordNoBenchmark(BenchmarkSelector.Kind.VM);
				continue;
			}
			ControlEvaluator.ComplianceResult cr =
					ControlEvaluator.evaluateControls(s.profile.vmControls(),
							passingSettings(s.profile.vmControls()), v.getKey());
			T.eq(0, cr.failCount, v.getKey() + " no failures");
			rollup.recordEvaluated(BenchmarkSelector.Kind.VM, s.bucket,
					cr.totalCount, cr.failCount, cr.unreadableCount, cr.score);
		}
		T.eq("VMware_SCG_8.0", profileByObject.get("vm-a"), "VM follows 8.0 host");
		T.eq("no benchmark for ESXi 10.0", profileByObject.get("vm-b"),
				"VM on 10.0 host has no benchmark");
		T.eq("VMware_SCG_6.7", profileByObject.get("vm-c"), "VM follows 6.7 host");

		// ---- vCenter, vDS (own version 9.0.0, ignored), portgroup
		String dvsOwnVersion = "9.0.0";
		T.check(!BenchmarkSelector.majorMinor(dvsOwnVersion).equals(
				BenchmarkSelector.majorMinor(vcVersion)),
				"fixture: vDS and vCenter versions differ");
		for (BenchmarkSelector.Kind k : new BenchmarkSelector.Kind[] {
				BenchmarkSelector.Kind.VCENTER, BenchmarkSelector.Kind.VDS,
				BenchmarkSelector.Kind.PORTGROUP}) {
			BenchmarkSelector.Selection s = sel.select(k,
					BenchmarkSelector.governingVersion(k, vcVersion, null));
			T.eq("VMware_SCG_9.1", s.profileName, k + " follows vCenter 9.1");
			rollup.recordEvaluated(k, s.bucket, 1, 0, 0, 100.0);
		}

		Map<String, Double> r = rollup.toStats();
		T.near(2, r.get(P + "Benchmark|SCG_6.7|objects"), "6.7: host + VM");
		T.near(1, r.get(P + "Benchmark|SCG_7.0|objects"), "7.0: host");
		T.near(2, r.get(P + "Benchmark|SCG_8.0|objects"), "8.0: host + VM");
		T.near(1, r.get(P + "Benchmark|SCG_9.0|objects"), "9.0: host");
		T.near(4, r.get(P + "Benchmark|SCG_9.1|objects"),
				"9.1: host + vCenter + vDS + portgroup");
		T.near(2, r.get(P + "Benchmark|none|objects"), "none: 10.0 host + VM");

		T.near(1, r.get(P + "Host|no_benchmark"), "one host without SCG");
		T.near(1, r.get(P + "VM|no_benchmark"), "one VM without SCG");
		T.near(2, r.get(P + "Host|non_compliant"),
				"8.0 host (fail) + 9.1 host (unreadable)");
		T.near(5, r.get(P + "Host|scored"), "4 live + 1 stale");
		T.near(1, r.get(P + "Host|scored_stale"), "stale host");
		T.near(2, r.get(P + "All|no_benchmark"), "all no benchmark");
		T.check(r.get(P + "Host|avg_score") < 100.0,
				"host average reflects the failure and the stale 50");

		System.out.println("MixedVersionSimulationTest: all assertions passed");
	}

	/**
	 * An advanced-settings map that satisfies every advanced_setting control
	 * in the slice, built from the profile's own expected values (the
	 * simulated host is "fully hardened" except where a test overrides it).
	 */
	private static Map<String, String> passingSettings(
			List<BenchmarkProfile.Control> slice) {
		Map<String, String> m = new HashMap<>();
		for (BenchmarkProfile.Control c : slice) {
			if (!"advanced_setting".equals(c.parameterKind)) continue;
			String e = c.expectedValue.trim();
			String lower = e.toLowerCase();
			if (lower.equals("not present")) continue;          // must be absent
			if (ControlEvaluator.isNonEmptyMode(e)) {
				m.put(c.parameter, "configured");
			} else if (ControlEvaluator.isNotEqualMode(e)) {
				m.put(c.parameter, "/vmfs/volumes/persistent");
			} else {
				m.put(c.parameter, ControlEvaluator.stripUndefinedSuffix(e));
			}
		}
		return m;
	}

	// Mirrors ComplianceAdapter.unreadableVimResult.
	private static ControlEvaluator.ComplianceResult unreadableVim(
			List<BenchmarkProfile.Control> controls, String name) {
		Object u = new Object();
		Map<String, Object> values = new HashMap<>();
		for (BenchmarkProfile.Control c : controls) {
			if (!"vim_property".equals(c.parameterKind)
					&& !"esxcli".equals(c.parameterKind)) continue;
			if (!c.isEvaluable()) continue;
			String p = c.configParameter;
			if (p == null || p.isEmpty() || "N/A".equals(p) || p.contains("\n")) {
				continue;
			}
			values.put(p, u);
		}
		return ControlEvaluator.evaluateVimProperties(controls, values, name, u);
	}

	// Mirrors ComplianceAdapter.mergeResults.
	private static ControlEvaluator.ComplianceResult merge(
			ControlEvaluator.ComplianceResult a,
			ControlEvaluator.ComplianceResult b) {
		int pass = a.passCount + b.passCount;
		int fail = a.failCount + b.failCount;
		int total = a.totalCount + b.totalCount;
		java.util.List<ControlEvaluator.ControlResult> m =
				new java.util.ArrayList<>(a.controlResults);
		m.addAll(b.controlResults);
		return new ControlEvaluator.ComplianceResult(a.hostname, pass, fail,
				total, a.unreadableCount + b.unreadableCount,
				total > 0 ? 100.0 * pass / total : 100.0, m);
	}
}
