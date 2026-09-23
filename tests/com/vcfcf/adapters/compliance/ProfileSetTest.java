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

		// Build 72 (review of build 71, BLOCKING): every scored row's read
		// path must exist on its resource kind. vds.network-reset-port read
		// config.policy.portConfigResetAtDisconnect on a distributed switch,
		// whose config.policy (DVSPolicy) has no such field: always
		// unreadable. The table below is the allowed path set per kind.
		int checked = 0;
		java.util.List<String> bad = new java.util.ArrayList<>();
		for (BenchmarkProfile p : all.values()) {
			for (BenchmarkProfile.Control c : p.controls) {
				BenchmarkSelector.Kind k = kindOf(c.resourceKind);
				if (k == null || !BenchmarkSelector.evaluatedFor(k, c)) continue;
				if ("advanced_setting".equals(c.parameterKind)) continue;
				checked++;
				String why = readPathProblem(c.resourceKind, c.readRecipe);
				if (why != null) bad.add(p.name + " " + c.controlId + ": " + why);
			}
		}
		T.check(checked > 100, "read-path guard covered " + checked + " rows");
		T.check(bad.isEmpty(), "read paths not on their kind: " + bad);
		T.check(readPathProblem("DistributedVirtualSwitch",
				"bool:config.policy.portConfigResetAtDisconnect") != null,
				"guard rejects the old vds.network-reset-port read");
		T.check(readPathProblem("DistributedVirtualPortgroup",
				"bool:config.policy.portConfigResetAtDisconnect") == null,
				"guard accepts the portgroup read");
		T.check(readPathProblem("VirtualMachine", "esxcli:system.tls.server.get:Profile")
				!= null, "esxcli only on hosts");
		for (String prof : new String[] {"VMware_SCG_7.0", "VMware_SCG_8.0",
				"VMware_SCG_9.0", "VMware_SCG_9.1"}) {
			T.check(find(all.get(prof).controls, "vds.network-reset-port") == null,
					prof + " has no vds.network-reset-port");
			BenchmarkProfile.Control rp =
					find(all.get(prof).controls, "dvpg.network-reset-port");
			T.check(rp != null && rp.isDvpgControl() && rp.isEvaluable(),
					prof + " scores dvpg.network-reset-port on the portgroup");
		}

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

	static BenchmarkSelector.Kind kindOf(String resourceKind) {
		switch (resourceKind) {
			case "HostSystem": return BenchmarkSelector.Kind.HOST;
			case "VirtualMachine": return BenchmarkSelector.Kind.VM;
			case "VCenterAdapterInstance": return BenchmarkSelector.Kind.VCENTER;
			case "ClusterComputeResource": return BenchmarkSelector.Kind.CLUSTER;
			case "DistributedVirtualSwitch": return BenchmarkSelector.Kind.VDS;
			case "DistributedVirtualPortgroup":
				return BenchmarkSelector.Kind.PORTGROUP;
			default: return null;
		}
	}

	/**
	 * Allowed vim25 read paths per resource kind (build 72). Source: the
	 * vSphere Web Services API data object types the collector reads,
	 * restricted to fields the canonical recipes use:
	 * <ul>
	 *   <li>VmwareDistributedVirtualSwitch.config = VMwareDVSConfigInfo
	 *       (extends DVSConfigInfo): defaultPortConfig (VMwareDVSPortSetting:
	 *       securityPolicy, ipfixEnabled, vlan, macManagementPolicy),
	 *       linkDiscoveryProtocolConfig, vspanSession,
	 *       networkResourceManagementEnabled. config.policy is DVSPolicy
	 *       (autoPreInstallAllowed, autoUpgradeAllowed,
	 *       partialUpgradeAllowed): NO portConfigResetAtDisconnect.</li>
	 *   <li>DistributedVirtualPortgroup.config = DVPortgroupConfigInfo:
	 *       defaultPortConfig (same setting type), policy =
	 *       VMwareDVSPortgroupPolicy (extends DVPortgroupPolicy:
	 *       portConfigResetAtDisconnect, securityPolicyOverrideAllowed,
	 *       ...).</li>
	 *   <li>ClusterComputeResource.configurationEx.vsanConfigInfo
	 *       (VsanClusterConfigInfo: enabled, defaultConfig).</li>
	 *   <li>HostSystem.config (HostConfigInfo) and VirtualMachine.config
	 *       (VirtualMachineConfigInfo) fields used by the recipes.</li>
	 * </ul>
	 * Style rules: esxcli and service_state read the host only; vami reads
	 * the vCenter appliance only. Adding a control with a new path means
	 * adding the path here, with its data-object source.
	 */
	static final Map<String, Set<String>> ALLOWED_PATHS = new java.util.HashMap<>();
	static {
		String[] setting = {
				"defaultPortConfig.securityPolicy.allowPromiscuous",
				"defaultPortConfig.securityPolicy.forgedTransmits",
				"defaultPortConfig.securityPolicy.macChanges",
				"defaultPortConfig.ipfixEnabled",
				"defaultPortConfig.vlan",
				"defaultPortConfig.macManagementPolicy.macLearningPolicy.enabled"};
		Set<String> dvs = new java.util.TreeSet<>();
		Set<String> dvpg = new java.util.TreeSet<>();
		for (String x : setting) { dvs.add("config." + x); dvpg.add("config." + x); }
		dvs.addAll(java.util.Arrays.asList(
				"config.linkDiscoveryProtocolConfig.operation",
				"config.vspanSession",
				"config.networkResourceManagementEnabled"));
		dvpg.addAll(java.util.Arrays.asList(
				"config.policy.portConfigResetAtDisconnect",
				"config.policy.securityPolicyOverrideAllowed"));
		ALLOWED_PATHS.put("DistributedVirtualSwitch", dvs);
		ALLOWED_PATHS.put("DistributedVirtualPortgroup", dvpg);
		ALLOWED_PATHS.put("ClusterComputeResource", new java.util.TreeSet<>(
				java.util.Arrays.asList(
						"configurationEx.vsanConfigInfo.enabled",
						"configurationEx.vsanConfigInfo.defaultConfig.autoClaimStorage",
						"configurationEx.vsanConfigInfo.defaultConfig.checksumEnabled")));
		ALLOWED_PATHS.put("HostSystem", new java.util.TreeSet<>(
				java.util.Arrays.asList(
						"config.encryptionState.mode",
						"config.encryptionState.requireSecureBoot",
						"config.encryptionState.requireExecuteInstalledOnly",
						"config.firewall.defaultPolicy.incomingBlocked",
						"config.lockdownMode",
						"config.dateTimeInfo.ntpConfig.server")));
		ALLOWED_PATHS.put("VirtualMachine", new java.util.TreeSet<>(
				java.util.Arrays.asList(
						"config.bootOptions.efiSecureBootEnabled",
						"config.flags.enableLogging",
						"config.ftEncryptionMode",
						"config.migrateEncryption",
						"config.version",
						"config.hardware.device")));
	}

	/** Null when the recipe's read exists on the kind, else the reason. */
	static String readPathProblem(String resourceKind, String recipe) {
		if (recipe == null || recipe.trim().isEmpty()) return "no recipe";
		String style = recipe.substring(0, Math.max(0, recipe.indexOf(':')));
		String path = recipe.substring(recipe.indexOf(':') + 1);
		switch (style) {
			case "esxcli":
			case "service_state":
				return "HostSystem".equals(resourceKind) ? null
						: style + " reads the ESX host only";
			case "vami":
				return "VCenterAdapterInstance".equals(resourceKind) ? null
						: "vami reads the vCenter appliance only";
			case "vm_hardware_device_absent":
				path = path.substring(0, path.lastIndexOf('.'));
				break;
			default:
				break;
		}
		Set<String> allowed = ALLOWED_PATHS.get(resourceKind);
		if (allowed == null) return "no vim25 reads defined for " + resourceKind;
		return allowed.contains(path) ? null
				: path + " is not a field of " + resourceKind;
	}

	static BenchmarkProfile.Control find(List<BenchmarkProfile.Control> cs,
			String id) {
		for (BenchmarkProfile.Control c : cs) {
			if (c.controlId.equals(id)) return c;
		}
		return null;
	}
}
