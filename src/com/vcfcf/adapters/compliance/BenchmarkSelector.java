package com.vcfcf.adapters.compliance;

import java.util.Collections;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * v3 (build 57): picks the benchmark profile for ONE object.
 *
 * <p>Two modes, set by the {@code benchmark_profile} connection setting:
 * <ul>
 *   <li><b>Auto (by version)</b>: each object is scored against the SCG
 *       matching its own product version. HostSystem uses its ESXi
 *       version; VirtualMachine uses its host's ESXi version; vCenter,
 *       cluster, distributed switch and distributed portgroup use the
 *       vCenter version (a vDS's own version, e.g. 9.0.0 under a 9.1.1
 *       vCenter, is deliberately NOT used: the switch is configured and
 *       hardened through that vCenter). The version's {@code major.minor}
 *       picks SCG 6.7 / 7.0 / 8.0 / 9.0 / 9.1 (8.0 U3 reports 8.0.3 and
 *       maps to 8.0). Any other version gets NO benchmark: profile name
 *       {@code "no benchmark for <ESXi|vCenter> X.Y"}, no score, no
 *       per-control results.</li>
 *   <li><b>Fixed</b> (any bundled profile or Custom): that profile for
 *       every object regardless of version (the pre-v3 behavior).</li>
 * </ul>
 *
 * <p>An unreadable version in Auto mode is NOT guessed and is NOT "no
 * benchmark" (build 58, review B2): the selection is
 * {@link Selection#versionUnreadable()}, which the caller treats as an
 * unreadable object (non-compliant, no alert cleanup), or resolves to the
 * benchmark the object had last cycle (see
 * {@link ComplianceDecisions#decide}). "No benchmark" is reserved for a
 * readable version with no bundled SCG.
 *
 * <p>No SDK dependencies: unit-testable with a plain JDK.
 */
public final class BenchmarkSelector {

	public static final String AUTO = "Auto (by version)";

	public static final String PRODUCT_ESXI = "ESXi";
	public static final String PRODUCT_VCENTER = "vCenter";

	/** Rollup benchmark bucket for objects with no applicable SCG. */
	public static final String BUCKET_NONE = "none";

	/**
	 * Rollup benchmark bucket for objects whose governing version could not
	 * be read and that had no benchmark to fall back on (build 58).
	 */
	public static final String BUCKET_UNKNOWN = "unknown";

	/** Object kinds, as used in the rollup keys. */
	public enum Kind {
		HOST("Host", PRODUCT_ESXI),
		VM("VM", PRODUCT_ESXI),
		VCENTER("vCenter", PRODUCT_VCENTER),
		CLUSTER("Cluster", PRODUCT_VCENTER),
		VDS("vDS", PRODUCT_VCENTER),
		PORTGROUP("Portgroup", PRODUCT_VCENTER);

		public final String rollupName;
		public final String product;

		Kind(String rollupName, String product) {
			this.rollupName = rollupName;
			this.product = product;
		}
	}

	private static final Pattern MAJOR_MINOR =
			Pattern.compile("^\\s*(\\d+)\\.(\\d+)");

	private final BenchmarkProfile fixed;                 // fixed mode
	private final Map<String, BenchmarkProfile> byScg;    // auto: "9.1" -> profile

	private BenchmarkSelector(BenchmarkProfile fixed,
			Map<String, BenchmarkProfile> byScg) {
		this.fixed = fixed;
		this.byScg = byScg;
	}

	/** Fixed mode: {@code profile} for every object. */
	public static BenchmarkSelector fixed(BenchmarkProfile profile) {
		if (profile == null) {
			throw new IllegalArgumentException("fixed profile is null");
		}
		return new BenchmarkSelector(profile, Collections.emptyMap());
	}

	/**
	 * Auto mode over the loaded bundled profiles, keyed by profile name
	 * ({@code VMware_SCG_9.1} etc., as returned by
	 * {@link BenchmarkLoader#loadAll}).
	 */
	public static BenchmarkSelector auto(
			Map<String, BenchmarkProfile> profilesByName) {
		Map<String, BenchmarkProfile> m = new java.util.HashMap<>();
		for (Map.Entry<String, BenchmarkProfile> e
				: profilesByName.entrySet()) {
			String scg = scgOfProfileName(e.getKey());
			if (scg != null) m.put(scg, e.getValue());
		}
		if (m.isEmpty()) {
			throw new IllegalArgumentException(
					"auto mode needs at least one bundled profile");
		}
		return new BenchmarkSelector(null, Collections.unmodifiableMap(m));
	}

	public boolean isAuto() {
		return fixed == null;
	}

	/**
	 * Select the benchmark for an object of {@code kind} whose governing
	 * product version is {@code version} (the ESXi version for a host, the
	 * host's ESXi version for a VM, the vCenter version for everything
	 * else; see {@link #governingVersion}). Ignored in fixed mode.
	 */
	public Selection select(Kind kind, String version) {
		if (fixed != null) {
			return Selection.of(fixed);
		}
		String mm = majorMinor(version);
		if (mm == null) {
			return Selection.unreadable("benchmark unknown: " + kind.product
					+ " version unreadable");
		}
		BenchmarkProfile p = byScg.get(mm);
		if (p == null) {
			return Selection.none("no benchmark for " + kind.product
					+ " " + mm);
		}
		return Selection.of(p);
	}

	/**
	 * The version that governs benchmark choice for {@code kind}: the host
	 * version for HOST and VM (for a VM the caller passes its host's
	 * version), the vCenter version for every other kind.
	 */
	public static String governingVersion(Kind kind, String vcenterVersion,
			String hostVersion) {
		switch (kind) {
			case HOST:
			case VM:
				return hostVersion;
			default:
				return vcenterVersion;
		}
	}

	/**
	 * True when the adapter actually evaluates {@code c} on an object of
	 * {@code kind}: the control must be evaluable (see
	 * {@link BenchmarkProfile.Control#isEvaluable()}) AND of a parameter kind
	 * the collector for {@code kind} reads. Host and VM: advanced_setting,
	 * vim_property, esxcli. vCenter: advanced_setting, vami_api. vDS,
	 * portgroup, cluster: vim_property, esxcli. The alert generator
	 * ({@code scripts/generate_compliance_alerts.py}) applies the same rule,
	 * so no alert is defined for a control that is never pushed.
	 */
	public static boolean evaluatedFor(Kind kind,
			BenchmarkProfile.Control c) {
		if (c == null || !c.isEvaluable()) return false;
		String pk = c.parameterKind;
		switch (kind) {
			case HOST:
			case VM:
				return "advanced_setting".equals(pk)
						|| "vim_property".equals(pk) || "esxcli".equals(pk);
			case VCENTER:
				return "advanced_setting".equals(pk) || "vami_api".equals(pk);
			default:
				return "vim_property".equals(pk) || "esxcli".equals(pk);
		}
	}

	/** {@code "8.0.3"} -> {@code "8.0"}; null when unparseable. */
	public static String majorMinor(String version) {
		if (version == null) return null;
		Matcher m = MAJOR_MINOR.matcher(version);
		if (!m.find()) return null;
		try {
			// Normalise "08.00" style noise; keep "9.1" / "10.0" shape.
			return Integer.parseInt(m.group(1)) + "."
					+ Integer.parseInt(m.group(2));
		} catch (NumberFormatException e) {
			return null;
		}
	}

	/** {@code VMware_SCG_9.1} -> {@code 9.1}; null for anything else. */
	static String scgOfProfileName(String profileName) {
		if (profileName == null) return null;
		String prefix = "VMware_SCG_";
		if (!profileName.startsWith(prefix)) return null;
		return profileName.substring(prefix.length());
	}

	/**
	 * Rollup benchmark bucket for a profile name: {@code VMware_SCG_9.1}
	 * -> {@code SCG_9.1}; {@code Custom} -> {@code Custom}.
	 */
	public static String bucketOf(String profileName) {
		String scg = scgOfProfileName(profileName);
		if (scg != null) return "SCG_" + scg;
		return profileName == null ? BUCKET_NONE : profileName;
	}

	/** The outcome of a selection: a profile, or no benchmark. */
	public static final class Selection {
		public final BenchmarkProfile profile;   // null when no benchmark
		public final String profileName;         // pushed as profile_name
		public final String bucket;              // rollup benchmark bucket
		private final boolean unreadableVersion;

		private Selection(BenchmarkProfile profile, String profileName,
				String bucket, boolean unreadableVersion) {
			this.profile = profile;
			this.profileName = profileName;
			this.bucket = bucket;
			this.unreadableVersion = unreadableVersion;
		}

		static Selection of(BenchmarkProfile p) {
			return new Selection(p, p.name, bucketOf(p.name), false);
		}

		static Selection none(String label) {
			return new Selection(null, label, BUCKET_NONE, false);
		}

		static Selection unreadable(String label) {
			return new Selection(null, label, BUCKET_UNKNOWN, true);
		}

		/** A READABLE version with no bundled SCG. */
		public boolean noBenchmark() {
			return profile == null && !unreadableVersion;
		}

		/** The governing version could not be read (never a guess). */
		public boolean versionUnreadable() {
			return unreadableVersion;
		}
	}
}
