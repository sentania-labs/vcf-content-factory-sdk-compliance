package com.vcfcf.adapters.compliance;

import java.util.Map;

/**
 * Version-to-benchmark selection (build 57), against the REAL bundled
 * profiles loaded from {@code profiles/canonical/} (run from the repo root).
 */
public final class BenchmarkSelectorTest {

	public static void main(String[] args) {
		Map<String, BenchmarkProfile> all = new BenchmarkLoader().loadAll(".");
		BenchmarkSelector auto = BenchmarkSelector.auto(all);
		T.check(auto.isAuto(), "auto selector reports auto");

		// major.minor parsing.
		T.eq("8.0", BenchmarkSelector.majorMinor("8.0.3"), "8.0 U3");
		T.eq("9.1", BenchmarkSelector.majorMinor("9.1.1"), "9.1.1");
		T.eq("10.0", BenchmarkSelector.majorMinor("10.0.0"), "10.0");
		T.eq("6.7", BenchmarkSelector.majorMinor("6.7.0"), "6.7");
		T.eq(null, BenchmarkSelector.majorMinor(""), "blank");
		T.eq(null, BenchmarkSelector.majorMinor(null), "null");
		T.eq(null, BenchmarkSelector.majorMinor("unknown"), "garbage");

		// Hosts by their own ESXi version.
		host(auto, "6.7.0", "VMware_SCG_6.7", "SCG_6.7");
		host(auto, "7.0.3", "VMware_SCG_7.0", "SCG_7.0");
		host(auto, "8.0.3", "VMware_SCG_8.0", "SCG_8.0");   // 8.0 U3
		host(auto, "8.0.2", "VMware_SCG_8.0", "SCG_8.0");
		host(auto, "9.0.0", "VMware_SCG_9.0", "SCG_9.0");
		host(auto, "9.1.1", "VMware_SCG_9.1", "SCG_9.1");

		// Unmapped and unreadable versions: no benchmark, never a guess.
		BenchmarkSelector.Selection s10 =
				auto.select(BenchmarkSelector.Kind.HOST, "10.0.0");
		T.check(s10.noBenchmark(), "ESXi 10.0 has no benchmark");
		T.eq("no benchmark for ESXi 10.0", s10.profileName, "10.0 label");
		T.eq("none", s10.bucket, "10.0 bucket");
		BenchmarkSelector.Selection s65 =
				auto.select(BenchmarkSelector.Kind.HOST, "6.5.0");
		T.eq("no benchmark for ESXi 6.5", s65.profileName, "6.5 label");
		BenchmarkSelector.Selection sNull =
				auto.select(BenchmarkSelector.Kind.HOST, null);
		T.check(sNull.noBenchmark(), "unreadable version has no benchmark");
		T.eq("no benchmark for ESXi (version unreadable)", sNull.profileName,
				"unreadable label");
		T.eq("no benchmark for vCenter 10.0",
				auto.select(BenchmarkSelector.Kind.VCENTER, "10.0.0")
						.profileName, "vCenter label");

		// A VM follows its HOST's version, not the vCenter's.
		String vc = "9.1.1";
		String vmHost = "8.0.3";
		T.eq("VMware_SCG_8.0", auto.select(BenchmarkSelector.Kind.VM,
				BenchmarkSelector.governingVersion(
						BenchmarkSelector.Kind.VM, vc, vmHost)).profileName,
				"VM follows host 8.0 under vCenter 9.1");
		T.eq("no benchmark for ESXi 10.0", auto.select(
				BenchmarkSelector.Kind.VM,
				BenchmarkSelector.governingVersion(
						BenchmarkSelector.Kind.VM, vc, "10.0.0")).profileName,
				"VM on an unmapped host has no benchmark");

		// vCenter, cluster, vDS and portgroup follow the vCenter version.
		// The lab case: a vDS reporting 9.0.0 under a 9.1.1 vCenter is
		// scored against SCG 9.1 (governingVersion never looks at the
		// object's own version).
		for (BenchmarkSelector.Kind k : new BenchmarkSelector.Kind[] {
				BenchmarkSelector.Kind.VCENTER, BenchmarkSelector.Kind.CLUSTER,
				BenchmarkSelector.Kind.VDS, BenchmarkSelector.Kind.PORTGROUP}) {
			T.eq("VMware_SCG_9.1", auto.select(k,
					BenchmarkSelector.governingVersion(k, "9.1.1", "7.0.3"))
					.profileName, k + " follows vCenter 9.1");
			T.eq("VMware_SCG_7.0", auto.select(k,
					BenchmarkSelector.governingVersion(k, "7.0.3", "9.1.1"))
					.profileName, k + " follows vCenter 7.0");
		}

		// Fixed mode forces the profile regardless of version.
		BenchmarkSelector fixed = BenchmarkSelector.fixed(
				all.get("VMware_SCG_9.0"));
		T.check(!fixed.isAuto(), "fixed selector is not auto");
		for (String v : new String[] {"6.7.0", "8.0.3", "10.0.0", null}) {
			BenchmarkSelector.Selection s =
					fixed.select(BenchmarkSelector.Kind.HOST, v);
			T.eq("VMware_SCG_9.0", s.profileName, "fixed 9.0 for " + v);
			T.check(!s.noBenchmark(), "fixed never no-benchmark");
		}
		T.eq("Custom", BenchmarkSelector.bucketOf("Custom"), "custom bucket");

		// evaluatedFor mirrors the collectors.
		BenchmarkProfile.Control adv = control("HostSystem", "advanced_setting",
				"");
		BenchmarkProfile.Control vami = control("VCenterAdapterInstance",
				"vami_api", "vami:access/ssh:enabled");
		BenchmarkProfile.Control vimNoRecipe = control("HostSystem",
				"vim_property", "");
		T.check(BenchmarkSelector.evaluatedFor(BenchmarkSelector.Kind.HOST,
				adv), "host reads advanced_setting");
		T.check(!BenchmarkSelector.evaluatedFor(BenchmarkSelector.Kind.VDS,
				adv), "vDS does not read advanced_setting");
		T.check(BenchmarkSelector.evaluatedFor(BenchmarkSelector.Kind.VCENTER,
				vami), "vCenter reads vami_api");
		T.check(!BenchmarkSelector.evaluatedFor(BenchmarkSelector.Kind.HOST,
				vimNoRecipe), "recipe-less vim_property not evaluated");

		System.out.println("BenchmarkSelectorTest: all assertions passed");
	}

	private static void host(BenchmarkSelector auto, String version,
			String wantProfile, String wantBucket) {
		BenchmarkSelector.Selection s =
				auto.select(BenchmarkSelector.Kind.HOST, version);
		T.check(!s.noBenchmark(), "ESXi " + version + " has a benchmark");
		T.eq(wantProfile, s.profileName, "ESXi " + version + " profile");
		T.eq(wantBucket, s.bucket, "ESXi " + version + " bucket");
		T.eq(wantProfile, s.profile.name, "ESXi " + version + " object");
	}

	static BenchmarkProfile.Control control(String kind, String pk,
			String recipe) {
		return new BenchmarkProfile.Control("x.test", "P0", kind, "VMWARE",
				"Some.Key", pk, "string", "1", "t", "d", "SCG-9.1:x", "fix",
				recipe);
	}
}
