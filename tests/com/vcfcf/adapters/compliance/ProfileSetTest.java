package com.vcfcf.adapters.compliance;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Bundled profile set (build 57): all five SCGs load, the manual-review
 * overlay demotes exactly the prose-expected controls, and the in-repo
 * normalizer deltas (7.0 key case, vmx minimum) are present. Run from the
 * repo root.
 */
public final class ProfileSetTest {

	public static void main(String[] args) throws Exception {
		BenchmarkLoader loader = new BenchmarkLoader();
		Map<String, BenchmarkProfile> all = loader.loadAll(".");
		T.eq(BenchmarkLoader.BUNDLED_PROFILES,
				new java.util.ArrayList<>(all.keySet()), "all five, in order");
		T.check(loader.loadAll(".") == all, "loadAll is cached");

		// Every overlay row names a control its profile really carries, and
		// that control is non-evaluable after load (never scored, never a
		// pass).
		Map<String, Set<String>> overlay = BenchmarkLoader.parseManualReview(
				Files.readAllLines(Paths.get("profiles", "manual_review.csv")));
		int rows = 0;
		for (Map.Entry<String, Set<String>> e : overlay.entrySet()) {
			BenchmarkProfile p = all.get(e.getKey());
			T.check(p != null, "overlay profile " + e.getKey() + " is bundled");
			for (String id : e.getValue()) {
				rows++;
				BenchmarkProfile.Control c = find(p.controls, id);
				T.check(c != null, e.getKey() + " carries " + id);
				T.check(!c.isEvaluable(), e.getKey() + " " + id
						+ " is manual review (not evaluable)");
				T.check(c.manualReview, e.getKey() + " " + id + " flagged");
			}
		}
		T.eq(37, rows, "overlay rows: 22 prose + 15 standard-switch (build 70)");
		int flagged = 0;
		for (BenchmarkProfile p : all.values()) flagged += p.manualReviewCount;
		T.eq(37, flagged, "every overlay row applied exactly once");
		T.eq(37, loader.lastManualReviewApplied(), "loader diagnostic");

		// Build 70 (Codex P1 on PR #12): no control sourced from the ESX
		// host (standard switch) may be scored on a distributed switch or
		// portgroup, in any profile. The collector reads the DVS / DVPG
		// config for these kinds, so a host-side standard-switch control
		// evaluated there would report the DVS's value (a false pass).
		for (BenchmarkProfile p : all.values()) {
			for (BenchmarkProfile.Control c : p.controls) {
				boolean dvKind = c.isDvsControl() || c.isDvpgControl();
				if (!dvKind || !c.isEvaluable()) continue;
				String ref = c.sourceRef;
				boolean hostSourced = ref.contains(":esxi-")
						|| ref.contains(":esx-");
				boolean standardSwitch = c.controlId.contains("standard")
						|| ref.toLowerCase().contains("standardswitch");
				T.check(!hostSourced && !standardSwitch, p.name + " "
						+ c.controlId + " (" + ref + ") is a host-side "
						+ "control scored on a distributed object");
			}
		}
		for (String prof : new String[] {"VMware_SCG_6.7", "VMware_SCG_7.0",
				"VMware_SCG_8.0"}) {
			for (String m : new String[] {"forged-transmit", "mac-changes",
					"promiscuous-mode"}) {
				String id = "vds.network-reject-" + m + "-standardswitch";
				T.check(!find(all.get(prof).controls, id).isEvaluable(),
						prof + " " + id + " not scored");
			}
		}
		for (String prof : new String[] {"VMware_SCG_9.0", "VMware_SCG_9.1"}) {
			for (String m : new String[] {"forged-transmit", "mac-changes",
					"promiscuous-mode"}) {
				String id = "vds.network-standard-reject-" + m;
				T.check(!find(all.get(prof).controls, id).isEvaluable(),
						prof + " " + id + " not scored");
			}
		}

		// A demoted control stays evaluable in a profile that does not list
		// it (overlay is per profile). esx.logs-remote: prose in 6.7/7.0/8.0.
		T.check(!find(all.get("VMware_SCG_8.0").controls, "esx.logs-remote")
				.isEvaluable(), "8.0 esx.logs-remote demoted");

		// The fixed-profile path applies the overlay too.
		BenchmarkProfile fixed91 = new BenchmarkLoader().load(
				"VMware_SCG_9.1", null, ".");
		T.check(!find(fixed91.controls, "esx.log-forwarding").isEvaluable(),
				"fixed 9.1 esx.log-forwarding demoted");

		// vm.virtual-hardware: scored with the minimum comparison in 9.1
		// (not in the overlay) and, since build 57, in 7.0.
		for (String prof : new String[] {"VMware_SCG_7.0", "VMware_SCG_9.1"}) {
			BenchmarkProfile.Control vh =
					find(all.get(prof).controls, "vm.virtual-hardware");
			T.check(vh.isEvaluable(), prof + " vm.virtual-hardware scored");
			T.check(ControlEvaluator.isVmxMinimumMode(vh.expectedValue),
					prof + " vm.virtual-hardware uses the vmx minimum");
		}
		// 8.0 / 9.0 keep exact equality (their descriptions say so).
		T.check(!ControlEvaluator.isVmxMinimumMode(find(
				all.get("VMware_SCG_8.0").controls, "vm.virtual-hardware")
				.expectedValue), "8.0 vmx is exact");

		// 7.0 esx.etc-issue carries the real ESX option key case.
		T.eq("Config.Etc.issue", find(all.get("VMware_SCG_7.0").controls,
				"esx.etc-issue").parameter, "7.0 etc-issue key case");

		T.check(BenchmarkLoader.parseManualReview(null).isEmpty(),
				"null overlay parses to empty");
		// Build 70: a MISSING overlay file fails the bundled load (it now
		// guards a false pass, not just a false fail).
		java.nio.file.Path empty = Files.createTempDirectory("noOverlay");
		try {
			BenchmarkLoader.loadManualReview(empty.toString());
			throw new AssertionError("missing overlay must fail the load");
		} catch (RuntimeException e) {
			T.check(String.valueOf(e.getMessage()).contains("false pass"),
					"actionable message: " + e.getMessage());
		} finally {
			Files.deleteIfExists(empty);
		}

		System.out.println("ProfileSetTest: all assertions passed");
	}

	static BenchmarkProfile.Control find(List<BenchmarkProfile.Control> cs,
			String id) {
		for (BenchmarkProfile.Control c : cs) {
			if (c.controlId.equals(id)) return c;
		}
		return null;
	}
}
