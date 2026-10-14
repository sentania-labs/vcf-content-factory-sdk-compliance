package com.vcfcf.adapters.compliance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Build 95 review W6: the bounded longest-prefix fallback (issue #17) leaves
 * every canonical vim_property recipe readable. Build 95 capped the
 * fallback at {@link VSphereClient#MAX_PREFIX_ATTEMPTS} lengths and, on
 * hosts and VMs, at two segments ({@link VSphereClient#minPrefixSegments}).
 * A recipe whose data only resolves at a prefix outside those bounds would
 * move from pass or fail to UNREADABLE (never a pass, but a regression).
 *
 * <p>{@link #RESOLVABLE} is, per recipe, the longest prefix vCenter's
 * PropertyCollector accepts, from the vim25 declared types: a property
 * defined only on a subtype (ClusterConfigInfoEx under
 * ComputeResourceConfigInfo, VMwareDVSPortSetting under DVPortSetting,
 * VMwareDVSConfigInfo under DVSConfigInfo, VMwareDVSPortgroupPolicy under
 * DVPortgroupPolicy) is rejected as InvalidProperty, so the prefix stops at
 * the declared parent and the rest is walked in the returned DOM. The test
 *
 * <ul>
 *   <li>walks every vim_property recipe the loaded canonical profiles read
 *       (a control demoted to manual review has no recipe) and
 *       fails on a recipe missing from the table (a new recipe needs its
 *       resolvable prefix stated) or a table row no profile uses;</li>
 *   <li>checks the resolvable length is one the per-object reader tries
 *       ({@link VSphereClient#prefixLengths} with the style's maximum) and
 *       one the bulk path keeps when it shortens an invalid path
 *       ({@link VSphereClient#shortenBulkPath});</li>
 *   <li>reads each recipe against a fake vCenter that rejects every path
 *       longer than the resolvable prefix, and checks the reader asks for
 *       the resolvable prefix and never for one shorter than the floor.</li>
 * </ul>
 * Run from the repo root.
 */
public final class Build95PrefixBoundsTest {

	/** "kind|recipe" -> resolvable prefix length (segments). */
	static final Map<String, Integer> RESOLVABLE = new LinkedHashMap<>();

	private static void row(String kind, String recipe, int len) {
		RESOLVABLE.put(kind + "|" + recipe, len);
	}

	static {
		// ClusterComputeResource.configurationEx is declared
		// ComputeResourceConfigInfo; vsanConfigInfo is on ClusterConfigInfoEx.
		row("ClusterComputeResource", "bool:configurationEx.vsanConfigInfo."
				+ "defaultConfig.autoClaimStorage", 1);
		// (cluster.object-checksum reads defaultConfig.checksumEnabled but is
		// manual review in every profile that has it, so it is not read.)
		// DVPortgroupConfigInfo.defaultPortConfig is declared DVPortSetting;
		// macManagementPolicy, securityPolicy and vlan are on
		// VMwareDVSPortSetting.
		row("DistributedVirtualPortgroup", "bool:config.defaultPortConfig."
				+ "macManagementPolicy.macLearningPolicy.enabled", 2);
		row("DistributedVirtualPortgroup", "bool_policy:config."
				+ "defaultPortConfig.securityPolicy.allowPromiscuous", 2);
		row("DistributedVirtualPortgroup", "bool_policy:config."
				+ "defaultPortConfig.securityPolicy.forgedTransmits", 2);
		row("DistributedVirtualPortgroup", "bool_policy:config."
				+ "defaultPortConfig.securityPolicy.macChanges", 2);
		row("DistributedVirtualPortgroup",
				"vlan_id_not:config.defaultPortConfig.vlan", 2);
		// DVPortgroupConfigInfo.policy is declared DVPortgroupPolicy, which
		// has portConfigResetAtDisconnect; securityPolicyOverrideAllowed is
		// on VMwareDVSPortgroupPolicy.
		row("DistributedVirtualPortgroup",
				"bool:config.policy.portConfigResetAtDisconnect", 3);
		row("DistributedVirtualPortgroup",
				"bool:config.policy.securityPolicyOverrideAllowed", 2);
		// DistributedVirtualSwitch.config is declared DVSConfigInfo, which
		// has networkResourceManagementEnabled and defaultPortConfig
		// (DVPortSetting); vspanSession and linkDiscoveryProtocolConfig
		// are on VMwareDVSConfigInfo, ipfixEnabled on VMwareDVSPortSetting.
		row("DistributedVirtualSwitch",
				"bool:config.networkResourceManagementEnabled", 2);
		row("DistributedVirtualSwitch",
				"bool_policy:config.defaultPortConfig.ipfixEnabled", 2);
		row("DistributedVirtualSwitch", "list_empty:config.vspanSession", 1);
		row("DistributedVirtualSwitch",
				"scalar:config.linkDiscoveryProtocolConfig.operation", 1);
		// HostConfigInfo: firewall (HostFirewallInfo) -> defaultPolicy
		// (HostFirewallDefaultPolicy) -> incomingBlocked, lockdownMode,
		// dateTimeInfo (HostDateTimeInfo) -> ntpConfig (HostNtpConfig) ->
		// server[]: all declared.
		row("HostSystem",
				"bool:config.firewall.defaultPolicy.incomingBlocked", 4);
		row("HostSystem", "scalar:config.lockdownMode", 2);
		row("HostSystem",
				"string_list_join:config.dateTimeInfo.ntpConfig.server", 3);
		// VirtualMachineConfigInfo: bootOptions, flags, ftEncryptionMode,
		// migrateEncryption, version, hardware: all declared.
		row("VirtualMachine", "bool:config.bootOptions.efiSecureBootEnabled",
				3);
		row("VirtualMachine", "bool:config.flags.enableLogging", 3);
		row("VirtualMachine", "scalar:config.ftEncryptionMode", 2);
		row("VirtualMachine", "scalar:config.migrateEncryption", 2);
		row("VirtualMachine", "scalar:config.version", 2);
		row("VirtualMachine", "vm_hardware_device_absent:config.hardware."
				+ "device.VirtualPCIPassthrough", 2);
	}

	public static void main(String[] args) throws Exception {
		List<String[]> recipes = canonicalRecipes();
		everyRecipeInTable(recipes);
		withinBounds(recipes);
		readerAsksForResolvablePrefix(recipes);
		System.out.println("Build95PrefixBoundsTest: all assertions passed ("
				+ recipes.size() + " recipes)");
	}

	/** {kind, recipe} of every vim_property recipe, service_state aside. */
	static List<String[]> canonicalRecipes() {
		TreeSet<String> seen = new TreeSet<>();
		for (BenchmarkProfile p : new BenchmarkLoader().loadAll(".").values()) {
			for (BenchmarkProfile.Control c : p.controls) {
				if (!"vim_property".equals(c.parameterKind)) continue;
				if (c.readRecipe == null || c.readRecipe.trim().isEmpty()) {
					continue;
				}
				seen.add(c.resourceKind + "|" + c.readRecipe.trim());
			}
		}
		List<String[]> out = new ArrayList<>();
		for (String s : seen) out.add(s.split("\\|", 2));
		return out;
	}

	static String style(String recipe) {
		return recipe.substring(0, recipe.indexOf(':'));
	}

	static String[] segments(String recipe) {
		return recipe.substring(recipe.indexOf(':') + 1).split("\\.");
	}

	/** The longest prefix the style's reader asks PropertyCollector for. */
	static int maxLen(String style, int segs) {
		switch (style) {
			case "scalar": case "bool": case "vlan_id_not":
				return segs;                  // walkToNode
			case "bool_policy": case "string_list_join": case "list_empty":
				return segs - 1;              // walkToParent
			case "vm_hardware_device_absent":
				return segs - 2;              // parent of the device list
			default:
				throw new AssertionError("style without a bound: " + style);
		}
	}

	static void everyRecipeInTable(List<String[]> recipes) {
		T.check(recipes.size() >= 20, "canonical recipes found: "
				+ recipes.size());
		java.util.Set<String> used = new java.util.HashSet<>();
		int service = 0;
		for (String[] r : recipes) {
			if ("service_state".equals(style(r[1]))) {
				service++;
				continue;   // exact config.service, no prefix fallback
			}
			String key = r[0] + "|" + r[1];
			used.add(key);
			T.check(RESOLVABLE.containsKey(key), "recipe has a resolvable "
					+ "prefix row (add one from the vim25 types): " + key);
		}
		T.check(service > 0, "service_state recipes present");
		for (String key : RESOLVABLE.keySet()) {
			T.check(used.contains(key), "table row used by a profile: " + key);
		}
		// service_state reads exactly config.service: two segments, at the
		// host floor, never the whole config.
		T.check(VSphereClient.minPrefixSegments("HostSystem") <= 2,
				"config.service is not under the host floor");
	}

	static void withinBounds(List<String[]> recipes) {
		for (String[] r : recipes) {
			String st = style(r[1]);
			if ("service_state".equals(st)) continue;
			String[] seg = segments(r[1]);
			int want = RESOLVABLE.get(r[0] + "|" + r[1]);
			int max = maxLen(st, seg.length);
			int[] tried = VSphereClient.prefixLengths(r[0], seg.length, max);
			boolean in = false;
			for (int len : tried) in |= len == want;
			T.check(in, r[0] + " " + r[1] + ": resolvable prefix " + want
					+ " is one of the lengths tried " + Arrays.toString(tried));
			T.check(want >= VSphereClient.minPrefixSegments(r[0]),
					r[0] + " " + r[1] + ": resolvable prefix at or above the "
					+ "floor");
			// Bulk: from the path bulkPaths asks for, shortening one
			// segment per InvalidProperty reaches the resolvable prefix
			// before the path would be dropped.
			String path = String.join(".", Arrays.copyOf(seg,
					"vm_hardware_device_absent".equals(st) ? seg.length - 2
					: max == seg.length ? seg.length : seg.length - 1));
			while (path != null && path.split("\\.").length > want) {
				path = VSphereClient.shortenBulkPath(r[0], path);
			}
			T.eq(String.join(".", Arrays.copyOf(seg, want)), path,
					r[0] + " " + r[1] + ": bulk path shortens to the "
					+ "resolvable prefix, not dropped");
		}
	}

	static void readerAsksForResolvablePrefix(List<String[]> recipes)
			throws Exception {
		for (String[] r : recipes) {
			String st = style(r[1]);
			if ("service_state".equals(st)) continue;
			String[] seg = segments(r[1]);
			int want = RESOLVABLE.get(r[0] + "|" + r[1]);
			String resolvable = String.join(".", Arrays.copyOf(seg, want));
			try (FakeVCenter f = new FakeVCenter()) {
				f.handler = q -> {
					String p = FakeVCenter.pathSets(q.body).get(0);
					String[] o = FakeVCenter.obj(q.body);
					if (p.split("\\.").length > want) {
						return FakeVCenter.invalidProperty(p);
					}
					return FakeVCenter.ok("RetrieveProperties",
							FakeVCenter.objectContent("returnval", o[0], o[1],
									FakeVCenter.vals()));
				};
				VSphereClient c = f.client();
				c.ensureConnected();
				c.readVimProperties(new VSphereClient.MoRef(r[0], "obj-1"),
						Arrays.asList(Build95CollectionTest.vim("c", r[0], "p",
								"true", r[1])));
				List<String> asked = new ArrayList<>();
				for (FakeVCenter.Req q : f.of("RetrieveProperties")) {
					asked.addAll(FakeVCenter.pathSets(q.body));
				}
				T.check(asked.contains(resolvable), r[0] + " " + r[1]
						+ ": reader asks for " + resolvable + ", asked "
						+ asked);
				int floor = VSphereClient.minPrefixSegments(r[0]);
				for (String a : asked) {
					T.check(a.split("\\.").length >= floor, r[0] + " " + r[1]
							+ ": never below the floor (" + a + ")");
				}
			}
		}
	}
}
