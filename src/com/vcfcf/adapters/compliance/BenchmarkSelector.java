package com.vcfcf.adapters.compliance;

import java.util.Collections;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * v3 (build 57): picks the benchmark profile for ONE object.
 *
 * <p><b>Auto (by version)</b>, the only mode since build 93 (the
 * Compliance Profile setting and its fixed choices are removed): each
 * object is scored against the SCG matching its own product version.
 * HostSystem uses its ESX version; VirtualMachine uses its host's ESX
 * version; vCenter, cluster, distributed switch and distributed portgroup
 * use the vCenter version (a vDS's own version, e.g. 9.0.0 under a 9.1.1
 * vCenter, is deliberately NOT used: the switch is configured and hardened
 * through that vCenter). The version's {@code major.minor} picks SCG 6.7 /
 * 7.0 / 8.0 / 9.0 / 9.1 (8.0 U3 reports 8.0.3 and maps to 8.0). Any other
 * version gets NO benchmark: profile name
 * {@code "no benchmark for <ESX|vCenter> X.Y"}, no score, no per-control
 * results. The overrides file's Profile pins (see {@link #withPins}) replace
 * the choice for the kinds they cover.
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

	public static final String PRODUCT_ESXI = "ESX";
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

	private final Map<String, BenchmarkProfile> byScg;    // "9.1" -> profile
	// Build 90: Profile pins from the overrides file, by kind. A pinned kind
	// takes its pinned profile in place of Auto.
	private final Map<Kind, BenchmarkProfile> pins;

	private BenchmarkSelector(Map<String, BenchmarkProfile> byScg,
			Map<Kind, BenchmarkProfile> pins) {
		this.byScg = byScg;
		this.pins = pins;
	}

	/**
	 * Build 90: this selector with the overrides file's Profile pins
	 * applied. {@code pinsByKind} holds one profile per pinned kind (the
	 * caller has already resolved an instance-wide pin into every kind it
	 * covers, and let a per-kind pin win over it). A pinned kind is scored
	 * against its pin whatever its version; every other kind stays on
	 * Auto (by version).
	 */
	public BenchmarkSelector withPins(Map<Kind, BenchmarkProfile> pinsByKind) {
		if (pinsByKind == null || pinsByKind.isEmpty()) return this;
		Map<Kind, BenchmarkProfile> m = new java.util.EnumMap<>(Kind.class);
		for (Map.Entry<Kind, BenchmarkProfile> e : pinsByKind.entrySet()) {
			if (e.getKey() != null && e.getValue() != null) {
				m.put(e.getKey(), e.getValue());
			}
		}
		return new BenchmarkSelector(byScg, Collections.unmodifiableMap(m));
	}

	/** Build 90: the pinned profile for {@code kind}, or null. */
	public BenchmarkProfile pinFor(Kind kind) {
		return pins.get(kind);
	}

	/**
	 * Auto (by version) over the loaded bundled profiles, keyed by profile name
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
		return new BenchmarkSelector(Collections.unmodifiableMap(m),
				Collections.<Kind, BenchmarkProfile>emptyMap());
	}

	/**
	 * Select the benchmark for an object of {@code kind} whose governing
	 * product version is {@code version} (the ESX version for a host, the
	 * host's ESX version for a VM, the vCenter version for everything
	 * else; see {@link #governingVersion}). Ignored for a pinned kind.
	 */
	public Selection select(Kind kind, String version) {
		BenchmarkProfile pinned = pins.get(kind);
		if (pinned != null) {
			return Selection.of(pinned);
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
	 * -> {@code SCG_9.1}; any other name is its own bucket.
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
