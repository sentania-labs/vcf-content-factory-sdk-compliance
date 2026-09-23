package com.vcfcf.adapters.compliance;

public final class ComplianceConfig {

	public final String vcenterHost;
	public final String username;
	public final String password;
	public final String benchmarkProfile;
	public final String customProfilePath;
	public final boolean allowInsecure;

	/**
	 * HOLD (owner decision pending, build 74): the adapter-instance setting
	 * "Read vCenter appliance settings" (identifier {@link #READ_APPLIANCE_KEY}).
	 * Off: the vCenter appliance (VAMI) controls load as manual review for
	 * this instance (not attempted, no score, no per-control alert). On: they
	 * are read and scored, which needs the collection account in the
	 * vsphere.local SSO group SystemConfiguration.Administrators (that group
	 * also grants appliance WRITE access; there is no read-only appliance
	 * role).
	 *
	 * <p>Changing the answer is a one-line default change here plus the
	 * matching {@code default=} on the describe.xml identifier. An absent or
	 * blank stored value (every instance created before build 74) takes this
	 * default.
	 */
	public static final boolean DEFAULT_READ_APPLIANCE = false;
	public static final String READ_APPLIANCE_KEY = "read_appliance_settings";
	public final boolean readApplianceSettings;

	public ComplianceConfig(String vcenterHost, String username, String password,
			String benchmarkProfile, String customProfilePath, String allowInsecure) {
		this(vcenterHost, username, password, benchmarkProfile,
				customProfilePath, allowInsecure, null);
	}

	public ComplianceConfig(String vcenterHost, String username, String password,
			String benchmarkProfile, String customProfilePath, String allowInsecure,
			String readApplianceSettings) {
		this.readApplianceSettings = parseReadAppliance(readApplianceSettings);
		this.vcenterHost = (vcenterHost != null && !vcenterHost.isEmpty())
				? vcenterHost : "localhost";
		this.username = (username != null) ? username : "";
		this.password = (password != null) ? password : "";
		this.benchmarkProfile = (benchmarkProfile != null && !benchmarkProfile.isEmpty())
				? benchmarkProfile : "VMware_SCG_8.0";
		this.customProfilePath = (customProfilePath != null) ? customProfilePath.trim() : "";
		// Strict-by-default (build 50, review B1): only the explicit literal
		// "true" opts into trust-all. null / blank / absent / any other value
		// parses to false -> platform trust store validation. This makes the
		// secure default actually engage for every existing and freshly-created
		// instance (which have no allowInsecure field), matching describe.xml
		// default="false" and the documented "platform trust by default".
		this.allowInsecure = "true".equalsIgnoreCase(allowInsecure);
	}

	/**
	 * v3: true when the instance selects the benchmark per object by
	 * version ({@link BenchmarkSelector#AUTO}). A blank / absent stored value
	 * stays on the pre-v3 fallback VMware_SCG_8.0 above, NOT Auto: an
	 * existing instance keeps behaving exactly as it did until someone edits
	 * it. New instances get Auto from the describe.xml default.
	 */
	public boolean isAuto() {
		return BenchmarkSelector.AUTO.equals(benchmarkProfile);
	}

	/** "true" / "false" (case-insensitive); anything else takes the default. */
	static boolean parseReadAppliance(String raw) {
		if (raw == null) return DEFAULT_READ_APPLIANCE;
		String v = raw.trim();
		if ("true".equalsIgnoreCase(v)) return true;
		if ("false".equalsIgnoreCase(v)) return false;
		return DEFAULT_READ_APPLIANCE;
	}

	public String baseUrl() {
		return "https://" + vcenterHost;
	}
}
